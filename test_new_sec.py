import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sec.os_protect import get_os_protection_module
from sec.net_analyzer import get_network_analyzer
from sec.cluster import create_cluster_node

def test_os_and_network():
    print("--- Тестирование OS Protection ---")
    os_protect = get_os_protection_module()
    health = os_protect.run_health_check()
    print(f"Статус ОС: {health['status']}")
    print(f"Привилегии: {health['privileges']['message']}")
    if health['resources']['warnings']:
        for w in health['resources']['warnings']:
             print(f"Warning: {w}")
    else:
        print(f"Загрузка CPU: {health['resources']['cpu_percent']}% | RAM: {health['resources']['ram_percent']}%")

    print("\n--- Тестирование Network Analyzer ---")
    net_analyzer = get_network_analyzer(max_syn_requests=50) # Искусственно занизили лимит
    net_status = net_analyzer.run_analysis()
    print(f"Сетевой статус: {net_status['status']}")
    print(net_status['syn_flood']['message'])
    print(net_status['abnormal_ips']['message'])

def run_cluster_node(role="master"):
    print(f"\n--- Запуск Cluster Node ({role.upper()}) ---")
    
    def on_failover_callback():
        print(">>> КОЛЛБЕК ПРОСРАБОТАЛ! Узел перешел в боевой режим (Master). Запускаю App.run()...")
        
    node = create_cluster_node(
        node_id=f"example_{role}", 
        role=role, 
        master_ip="127.0.0.1", 
        master_port=8888,
        sync_dir="." # Для тестов синхронизируем текущую папку
    )
    node.on_failover = on_failover_callback
    node.start()
    
    try:
        if role == "master":
            print("[Master] Работаю... Нажмите Ctrl+C чтобы остановить и проверить Failover на Slave (если запущен).")
            while True: time.sleep(1)
        else:
            print("[Slave] Нахожусь в режиме ожидания. Нажмите Ctrl+C для выхода.")
            while True: time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n[Узел {role}] Остановка...")
        node.stop()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            test_os_and_network()
        elif sys.argv[1] == "master":
            run_cluster_node("master")
        elif sys.argv[1] == "slave":
            run_cluster_node("slave")
        else:
            print("Доступные команды: test, master, slave")
    else:
        print("Запустите: python test_new_sec.py [test | master | slave]")
