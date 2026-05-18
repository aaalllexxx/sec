"""
sec.__auto_cluster — Локальная кластеризация на одном сервере.
Запускает копии приложения на нескольких портах в отдельных процессах.
Подключается одной строкой: LocalCluster(app, ports=[5000, 5001])
"""
import os
import sys
import time
import signal
import logging
import threading
import subprocess

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("sec.auto_cluster")


class LocalCluster:
    """
    Менеджер локального Active-Passive кластера.
    
    Поднимает несколько копий Flask-приложения на разных портах 
    на одном сервере. Первая нода = Active (Master), остальные = Passive (Slave).
    Если Master падает, первый Slave автоматически становится Master.
    
    Подключение:
        from sec.auto_cluster import LocalCluster
        
        cluster = LocalCluster(app, ports=[5000, 5001, 5002])
        cluster.run()   # Вместо app.run()
    """

    def __init__(self, app, ports: list = None, 
                 heartbeat_interval: float = 2.0,
                 failover_timeout: float = 6.0):
        """
        Args:
            app: Экземпляр AEngineApps App.
            ports: Список портов для нод. Первый = Master. По умолчанию [5000, 5001].
            heartbeat_interval: Интервал проверки жизни нод (сек).
            failover_timeout: Таймаут перед объявлением ноды мёртвой (сек).
        """
        self.app = app
        self.ports = ports or [5000, 5001]
        self.heartbeat_interval = heartbeat_interval
        self.failover_timeout = failover_timeout

        self._processes = {}       # port -> Process
        self._roles = {}           # port -> "master" | "slave"
        self._manager = None
        self._shared_state = None
        self._running = False

    def run(self):
        """
        Запускает кластер. Вызывается ВМЕСТО app.run().
        Первая нода = Master, остальные = Slave.
        """
        cluster_port = os.environ.get("AENGINE_CLUSTER_PORT")
        if cluster_port:
            # We are inside a child worker process! Bypass normal cluster startup.
            port = int(cluster_port)
            role = os.environ.get("AENGINE_CLUSTER_ROLE", "slave")
            self._node_worker(port, role)
            return

        if len(self.ports) < 2:
            logger.warning("[Cluster] Менее 2 портов — кластеризация бессмысленна. Запускаем обычный сервер.")
            self.app.run(port=self.ports[0])
            return

        self._running = True

        # Храним состояние локально (так как subprocess не имеет общего Manager)
        # Heartbeat будет реализован через проверку процессов O.S. (или API, если нужно в будущем)
        self._shared_state = {}
        self._shared_state["master_port"] = self.ports[0]
        self._shared_state["active_ports"] = list(self.ports)

        logger.info("[Cluster] Запуск кластера на портах: %s", self.ports)
        logger.info("[Cluster] Master: порт %d", self.ports[0])

        # Назначаем роли
        for i, port in enumerate(self.ports):
            role = "master" if i == 0 else "slave"
            self._roles[port] = role

        # Запускаем все ноды
        for port in self.ports:
            self._start_node(port)

        # Запускаем watchdog в основном процессе
        try:
            self._watchdog_loop()
        except KeyboardInterrupt:
            logger.info("[Cluster] Получен сигнал остановки.")
            self.shutdown()

    def shutdown(self):
        """Останавливает все ноды кластера."""
        self._running = False
        logger.info("[Cluster] Остановка всех нод...")
        for port, proc in list(self._processes.items()):
            is_alive = proc.is_alive() if hasattr(proc, 'is_alive') else (proc.poll() is None)
            if is_alive:
                proc.terminate()
                if hasattr(proc, 'join'):
                    proc.join(timeout=2)
                else:
                    proc.wait(timeout=2)
                logger.info("[Cluster] Нода :%d остановлена.", port)
        self._processes.clear()

    def get_status(self) -> dict:
        """Возвращает текущее состояние кластера."""
        nodes = []
        for port in self.ports:
            proc = self._processes.get(port)
            alive = False
            if proc:
                alive = proc.is_alive() if hasattr(proc, 'is_alive') else (proc.poll() is None)
            nodes.append({
                "port": port,
                "role": self._roles.get(port, "unknown"),
                "alive": alive,
                "pid": proc.pid if proc and alive else None,
            })
        return {
            "master_port": self._shared_state.get("master_port") if self._shared_state else None,
            "nodes": nodes,
            "total": len(self.ports),
            "alive": sum(1 for n in nodes if n["alive"]),
        }

    # ─────────── Внутренние методы ───────────

    def _start_node(self, port: int):
        """Запускает одну ноду в отдельном процессе через subprocess."""
        role = self._roles[port]
        
        env = os.environ.copy()
        env["AENGINE_CLUSTER_PORT"] = str(port)
        env["AENGINE_CLUSTER_ROLE"] = role
        
        proc = subprocess.Popen(
            [sys.executable] + sys.argv,
            env=env
        )
        self._processes[port] = proc
        logger.info("[Cluster] Нода :%d запущена (role=%s, pid=%d)", port, role, proc.pid)

    def _node_worker(self, port: int, role: str):
        """Рабочий процесс ноды. Запускает Flask на указанном порту."""
        try:
            # Переопределяем порт в конфиге приложения для этой ноды
            self.app.config["port"] = port
            self.app.config["host"] = "0.0.0.0"
            # Отключаем debug/reloader в кластере — reloader мешает watchdog
            self.app.config["debug"] = False
            os.environ["AENGINE_CLUSTER_ROLE"] = role

            if role == "master":
                logger.info("[Node:%d] Запуск в режиме MASTER", port)
            else:
                logger.info("[Node:%d] Запуск в режиме SLAVE (standby)", port)

            # App.run() читает host/port из self.config, аргументов не принимает
            self.app.run()
        except Exception as e:
            logger.error("[Node:%d] Ошибка: %s", port, e)

    def _watchdog_loop(self):
        """Основной цикл наблюдения за нодами в главном процессе."""
        while self._running:
            time.sleep(self.heartbeat_interval)

            current_master = self._shared_state.get("master_port")

            for port, proc in list(self._processes.items()):
                is_alive = proc.poll() is None if hasattr(proc, 'poll') else proc.is_alive()
                if not is_alive:
                    role = self._roles.get(port, "?")
                    logger.warning("[Cluster] Нода :%d (%s) упала!", port, role)

                    if port == current_master:
                        # Master упал — нужен failover
                        logger.critical("[Cluster] MASTER (%d) потерян! Запуск failover...", port)
                        self._failover(port)
                    else:
                        # Slave упал — перезапускаем
                        logger.info("[Cluster] Перезапуск slave :%d...", port)
                        self._start_node(port)

    def _failover(self, dead_master_port: int):
        """Переключение: первый живой Slave становится Master."""
        new_master = None
        for port in self.ports:
            if port == dead_master_port:
                continue
            proc = self._processes.get(port)
            is_alive = False
            if proc:
                is_alive = proc.poll() is None if hasattr(proc, 'poll') else proc.is_alive()
            if is_alive:
                new_master = port
                break

        if new_master:
            self._roles[new_master] = "master"
            self._shared_state["master_port"] = new_master
            logger.critical("[Cluster] FAILOVER: Новый Master -> :%d", new_master)
        else:
            logger.critical("[Cluster] Все ноды мертвы! Перезапуск Master на :%d...", dead_master_port)

        # Перезапускаем упавшую ноду как Slave
        self._roles[dead_master_port] = "slave"
        self._start_node(dead_master_port)


__all__ = ['LocalCluster']
