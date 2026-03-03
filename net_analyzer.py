from .__net_analyzer import NetworkAnalyzer

def get_network_analyzer(app=None, max_syn_requests: int = 100, max_connections_per_ip: int = 50) -> NetworkAnalyzer:
    """
    Возвращает экземпляр сетевого анализатора для поиска SYN-хлудов и аномальных IP соединений.
    """
    return NetworkAnalyzer(app=app, max_syn_requests=max_syn_requests, max_connections_per_ip=max_connections_per_ip)
