import os
import time
import socket
import threading
import json
import tarfile
import io

class ClusterNode:
    """
    Узел кластера Active-Passive.
    Обеспечивает отказоустойчивость, синхронизацию файлов и Heartbeat.
    """
    
    def __init__(self, node_id: str, role: str, master_ip: str, master_port: int, 
                 sync_dir: str = ".", heartbeat_interval: int = 2, timeout: int = 6):
        """
        :param node_id: Уникальное имя ноды.
        :param role: "master" (Active) или "slave" (Passive).
        :param master_ip: IP-адрес Master ноды (для Slave - куда стучаться, для Master - на каком IP слушать).
        :param master_port: Порт для UDP Heartbeat и TCP File Sync.
        :param sync_dir: Директория для синхронизации кода.
        :param heartbeat_interval: Как часто Master шлет пульс (в секундах).
        :param timeout: Через сколько секунд отсутствия пульса Slave становится Master'ом.
        """
        self.node_id = node_id
        self.role = role.lower()
        self.master_ip = master_ip
        self.master_port = master_port
        self.sync_dir = sync_dir
        
        self.heartbeat_interval = heartbeat_interval
        self.timeout = timeout
        self.last_heartbeat = time.time()
        
        self.running = False
        self.on_failover = None  # Коллбек при смене роли Slave -> Master
        
    def _create_project_archive(self) -> bytes:
        """Создает tar.gz архив проекта в памяти (Master)."""
        mem_file = io.BytesIO()
        with tarfile.open(fileobj=mem_file, mode="w:gz") as tar:
            for root, dirs, files in os.walk(self.sync_dir):
                # Исключаем скрытые папки (например .git) и саму СУБД/Логи, чтобы не затереть
                if ".git" in root or "__pycache__" in root:
                     continue
                for file in files:
                    if file.endswith((".py", ".html", ".css", ".json", ".js", ".md")):
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, self.sync_dir)
                        tar.add(file_path, arcname=arcname)
        mem_file.seek(0)
        return mem_file.read()

    def _extract_project_archive(self, archive_data: bytes):
        """Распаковывает полученный tar.gz архив поверх текущей директории (Slave)."""
        mem_file = io.BytesIO(archive_data)
        with tarfile.open(fileobj=mem_file, mode="r:gz") as tar:
            tar.extractall(path=self.sync_dir)

    def _master_sync_server(self):
        """TCP сервер на Master для отдачи файлов."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.master_ip, self.master_port + 1)) # TCP порт пульса + 1
        server.listen(5)
        
        while self.running and self.role == "master":
            try:
                server.settimeout(1.0)
                client, addr = server.accept()
                with client:
                    req = client.recv(1024).decode()
                    if req == "SYNC_REQUEST":
                        print(f"[Cluster] Нода {addr} запросила синхронизацию файлов.")
                        archive = self._create_project_archive()
                        # Сначала шлем размер
                        client.sendall(len(archive).to_bytes(8, byteorder='big'))
                        # Затем сам архив
                        client.sendall(archive)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Cluster] Ошибка в сервере синхронизации: {e}")
        server.close()

    def _slave_request_sync(self):
        """Slave запрашивает файлы у Master перед запуском."""
        print(f"[Cluster] Попытка синхронизации с Master ({self.master_ip}:{self.master_port+1})...")
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect((self.master_ip, self.master_port + 1))
            client.sendall(b"SYNC_REQUEST")
            
            # Получаем размер
            size_data = client.recv(8)
            expected_size = int.from_bytes(size_data, byteorder='big')
            
            # Получаем файл
            received_data = b""
            while len(received_data) < expected_size:
                chunk = client.recv(4096)
                if not chunk: break
                received_data += chunk
                
            self._extract_project_archive(received_data)
            print("[Cluster] Синхронизация успешно завершена. Файлы обновлены.")
            client.close()
        except Exception as e:
            print(f"[Cluster] Не удалось синхронизироваться с Master: {e}")

    def _heartbeat_sender(self):
        """Поток отправки пульса (для Master)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Разрешаем broadcast, если нужно (в примере отправляем на конкретный IP или broadcast)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while self.running and self.role == "master":
            msg = json.dumps({"node_id": self.node_id, "status": "active"}).encode()
            try:
                sock.sendto(msg, (self.master_ip, self.master_port))
            except Exception as e:
                pass
            time.sleep(self.heartbeat_interval)
        sock.close()

    def _heartbeat_listener(self):
        """Поток прослушивания пульса (для Slave)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", self.master_port))
        sock.settimeout(1.0)
        
        while self.running and self.role == "slave":
            try:
                data, _ = sock.recvfrom(1024)
                # Если получили статус, значит Master жив
                self.last_heartbeat = time.time()
            except socket.timeout:
                if time.time() - self.last_heartbeat > self.timeout:
                    print(f"[Cluster] ВНИМАНИЕ: Heartbeat от Master отсутствует более {self.timeout}с.")
                    self._promote_to_master()
            except Exception as e:
                pass
        sock.close()

    def _promote_to_master(self):
        """Смена роли с Slave на Master (Failover)."""
        print(f"[Cluster] Нода '{self.node_id}' повышена до Master! Запускаем сервисы.")
        self.role = "master"
        
        # Запускаем треды мастера
        threading.Thread(target=self._heartbeat_sender, daemon=True).start()
        threading.Thread(target=self._master_sync_server, daemon=True).start()
        
        if self.on_failover:
            self.on_failover()

    def start(self):
        """Запуск кластера."""
        self.running = True
        
        if self.role == "slave":
            self._slave_request_sync() # Синхронизируемся до старта
            self.last_heartbeat = time.time()
            threading.Thread(target=self._heartbeat_listener, daemon=True).start()
            print(f"[Cluster] Нода '{self.node_id}' запущена как SLAVE. Ожидание пульса...")
            
        elif self.role == "master":
            threading.Thread(target=self._master_sync_server, daemon=True).start()
            threading.Thread(target=self._heartbeat_sender, daemon=True).start()
            print(f"[Cluster] Нода '{self.node_id}' запущена как MASTER. Раздаем пульс.")

    def stop(self):
        self.running = False


__all__ = ['ClusterAdmin']
