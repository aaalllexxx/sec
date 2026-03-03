from .__cluster import ClusterNode

def create_cluster_node(node_id: str, role: str, master_ip: str, master_port: int, 
                 sync_dir: str = ".", heartbeat_interval: int = 2, timeout: int = 6) -> ClusterNode:
    """
    Инициализирует узел кластера.
    
    :param node_id: Имя ноды (например, 'node_1')
    :param role: 'master' или 'slave'
    :param master_ip: IP мастера (или broadcast адрес)
    :param master_port: Порт для обмена пакетами кластера
    :param sync_dir: корневая папка проекта для синхронизации
    """
    return ClusterNode(
        node_id=node_id, 
        role=role, 
        master_ip=master_ip, 
        master_port=master_port, 
        sync_dir=sync_dir,
        heartbeat_interval=heartbeat_interval,
        timeout=timeout
    )
