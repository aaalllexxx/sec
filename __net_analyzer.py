import psutil
from collections import defaultdict
import time

class NetworkAnalyzer:
    """
    Модуль сетевого анализатора.
    Анализирует сетевые соединения хоста с помощью psutil.
    Обнаруживает потенциальные SYN_FLOOD атаки и аномальные скопления соединений
    с одного IP-адреса.
    """
    
    def __init__(self, app=None, max_syn_requests: int = 100, max_connections_per_ip: int = 50):
        self.max_syn_requests = max_syn_requests
        self.max_connections_per_ip = max_connections_per_ip
        
        if app:
            self.attach(app)

    def attach(self, app):
        """Автоматическая интеграция с приложением."""
        app.before_request(self._auto_scan_hook)

    def _auto_scan_hook(self):
        """Хук, вызываемый перед каждым HTTP запросом."""
        flood_check = self.detect_syn_flood()
        if flood_check["status"] == "danger":
            import logging
            logging.critical(f"[Net Analyzer] {flood_check['message']}")
            from flask import abort
            abort(503, description="Service Unavailable: SYN Flood Detected")

    def _get_connections(self):
        """Безопасное получение списка соединений."""
        try:
            return psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            # На некоторых ОС для просмотра всех портов нужны root-права
            # Возвращаем пустой список или логируем ошибку
            return []

    def detect_syn_flood(self) -> dict:
        """
        Проверка на наличие SYN Flood атаки (много полуоткрытых соединений).
        """
        syn_count = 0
        connections = self._get_connections()
        
        for conn in connections:
            if conn.status == psutil.CONN_SYN_RECV or conn.status == psutil.CONN_SYN_SENT:
                syn_count += 1
                
        is_flooding = syn_count > self.max_syn_requests
        
        return {
            "status": "danger" if is_flooding else "ok",
            "syn_count": syn_count,
            "message": f"Обнаружено аномальное количество SYN запросов ({syn_count}). Возможна атака SYN Flood!" if is_flooding else "SYN Flood не обнаружен."
        }

    def detect_abnormal_ips(self) -> dict:
        """
        Ищет IP-адреса, которые открыли слишком много 'ESTABLISHED' соединений
        одновременно (возможный DoS/DDoS с ботнета).
        """
        ip_counts = defaultdict(int)
        connections = self._get_connections()
        
        for conn in connections:
            # Мониторим только активные TCP соединения
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                remote_ip = conn.raddr.ip
                # Игнорируем локальные коннекты для тестов (в проде стоит аккуратнее фильтровать)
                if remote_ip not in ["127.0.0.1", "::1"]:
                    ip_counts[remote_ip] += 1
        
        abnormal_ips = {}
        for ip, count in ip_counts.items():
            if count > self.max_connections_per_ip:
                abnormal_ips[ip] = count
                
        is_danger = len(abnormal_ips) > 0
        
        return {
            "status": "warning" if is_danger else "ok",
            "abnormal_ips": abnormal_ips,
            "message": f"Обнаружены IP с аномальным количеством соединений: {abnormal_ips}" if is_danger else "Аномальных IP не обнаружено."
        }

    def run_analysis(self) -> dict:
        """Запускает полную проверку сети."""
        syn_check = self.detect_syn_flood()
        ip_check = self.detect_abnormal_ips()
        
        overall_status = "ok"
        if ip_check["status"] != "ok":
            overall_status = "warning"
        if syn_check["status"] == "danger":
            overall_status = "danger"
            
        return {
            "status": overall_status,
            "syn_flood": syn_check,
            "abnormal_ips": ip_check
        }
