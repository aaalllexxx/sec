import psutil
from collections import defaultdict
import time

class NetworkAnalyzer:
    """
    Модуль сетевого анализатора.
    Анализирует сетевые соединения хоста с помощью psutil.
    """
    
    def __init__(self, app=None, max_syn_requests: int = 100, max_connections_per_ip: int = 50):
        self.max_syn_requests = max_syn_requests
        self.max_connections_per_ip = max_connections_per_ip
        
        # Для аномалийного анализа
        self.traffic_history = []  # Хранит количество соединений за последние 60 проверок
        self.max_history = 60
        
        if app:
            self.attach(app)

    def attach(self, app):
        """Автоматическая интеграция с приложением."""
        try:
            import AEngineApps.sec_config as sec_config
            if not getattr(sec_config, "MODULES_STATUS", {}).get("net_analyzer", True):
                return
        except ImportError: pass

        app.before_request(self._auto_scan_hook)

    def _auto_scan_hook(self):
        """Хук, вызываемый перед каждым HTTP запросом."""
        analysis = self.run_analysis()
        if analysis["status"] == "danger":
            import logging
            logging.critical(f"[Net Analyzer] Critical Network Anomaly Detected!")

    def _get_connections(self):
        """Безопасное получение списка соединений."""
        try:
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            return []

    def detect_syn_flood(self) -> dict:
        """Проверка на наличие SYN Flood атаки."""
        connections = self._get_connections()
        syn_count = sum(1 for conn in connections if conn.status in (psutil.CONN_SYN_RECV, psutil.CONN_SYN_SENT))
        is_flooding = syn_count > self.max_syn_requests
        
        return {
            "status": "danger" if is_flooding else "ok",
            "syn_count": syn_count,
            "message": f"SYN Flood! ({syn_count} SYN)" if is_flooding else "SYN OK"
        }

    def detect_abnormal_ips(self) -> dict:
        """Ищет IP с аномальным количеством соединений."""
        ip_counts = defaultdict(int)
        connections = self._get_connections()
        
        for conn in connections:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                ip_counts[conn.raddr.ip] += 1
        
        abnormal = {ip: count for ip, count in ip_counts.items() if count > self.max_connections_per_ip}
        is_danger = len(abnormal) > 0
        
        return {
            "status": "warning" if is_danger else "ok",
            "abnormal_ips": abnormal,
            "message": f"IP Flood: {abnormal}" if is_danger else "IPs OK"
        }

    def detect_traffic_anomaly(self) -> dict:
        """Аномалийный анализ: детекция отклонений от среднего поведения."""
        connections = self._get_connections()
        current_count = len(connections)
        
        # Обновляем историю
        self.traffic_history.append(current_count)
        if len(self.traffic_history) > self.max_history:
            self.traffic_history.pop(0)
            
        if len(self.traffic_history) < 10:
            return {"status": "ok", "message": "Gathering baseline..."}
            
        avg = sum(self.traffic_history) / len(self.traffic_history)
        is_spike = current_count > avg * 3 and current_count > 20
        
        return {
            "status": "danger" if is_spike else "ok",
            "current_count": current_count,
            "baseline_avg": round(avg, 2),
            "message": f"Traffic Spike! ({current_count} vs avg {avg:.1f})" if is_spike else "Traffic Stable"
        }

    def detect_unusual_protocols(self) -> dict:
        """Проверка на наличие нетипичных протоколов или портов."""
        connections = self._get_connections()
        alerts = []
        
        # Подозрительные порты (пример: порты типичных троянов или C2)
        SUSPECT_PORTS = {4444, 6667, 1337, 31337}
        
        for conn in connections:
            if conn.laddr and conn.laddr.port in SUSPECT_PORTS:
                alerts.append(f"Подозрительный локальный порт: {conn.laddr.port}")
            if conn.status == psutil.CONN_LISTEN and conn.type == 2: # SOCK_DGRAM (UDP) listen
                # UDP-прослушка иногда подозрительна для веб-сервера
                pass

        return {
            "status": "warning" if alerts else "ok",
            "alerts": alerts
        }

    def run_analysis(self) -> dict:
        """Запускает полную проверку сети."""
        syn = self.detect_syn_flood()
        ips = self.detect_abnormal_ips()
        anomaly = self.detect_traffic_anomaly()
        proto = self.detect_unusual_protocols()
        
        # Итоговый статус
        statuses = [syn["status"], ips["status"], anomaly["status"], proto["status"]]
        overall = "ok"
        if "danger" in statuses: overall = "danger"
        elif "warning" in statuses: overall = "warning"
            
        return {
            "status": overall,
            "syn_flood": syn,
            "abnormal_ips": ips,
            "anomaly": anomaly,
            "protocols": proto
        }

def get_network_analyzer(app=None, max_syn_requests: int = 100, max_connections_per_ip: int = 50) -> NetworkAnalyzer:
    """
    Возвращает экземпляр сетевого анализатора для поиска SYN-хлудов и аномальных IP соединений.
    """
    return NetworkAnalyzer(app=app, max_syn_requests=max_syn_requests, max_connections_per_ip=max_connections_per_ip)
