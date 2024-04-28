import os
import frida
import sys
import json
import hashlib
import logging
import time
import threading
from PIL import Image
from watchdog.observers import Observer
from watchdog.events import FileSystemEvent, FileSystemEventHandler

#DESKPATH = os.path.join(os.path.expanduser('~'), '바탕 화면')
DESKPATH = os.path.join(os.path.expanduser('~'), 'OneDrive','Desktop')  # 자동으로 사용자 onedrive 유저 네임까지 
HOOKSCPATH = os.path.join(DESKPATH,'Analyzer','hook_script.js')
DECOYPATHS = os.path.join(os.path.expanduser('~'), 'OneDrive','문서')
RANSOMWAREPATH = os.path.join(os.path.expanduser('~'), 'Downloads')
LOGPATH = os.path.join(DESKPATH,'Analyzer','log')
BUF_SIZE = 65536
FILENUM = 5
file_path = "C:\\Users\\lmkso\\Downloads"
file_name, file_extension= os.path.splitext(file_path)

    
# 랜섬웨어로 인해 변경된 파일 확인 
ransomeware_extensions = ['.encryted','.locked','.crypto']  #좀 더 추가~

for root, dirs, files in os.walk(file_path):  # 경로, 하위 폴더 목록, 파일 목록
    for file in files:
        if any(file.endswith(ext) for ext in ransomeware_extensions):
            print(f"랜섬웨어에 의해 변경된 파일 발견:  {os.path.join (root, file)}")
        else:
            print("이상 없습니다")

# 미끼 파일 생성
class MakeDecoy: # 디코이= 미끼파일 만드는 코드
    def __init__(self, number_of_files):
        self.number_of_files = number_of_files
        self.documents_folder = DECOYPATHS

    def create_text_files(self):
        for i in range(self.number_of_files):
            text_file_path = os.path.join(self.documents_folder, f'decoy_text_{i}.txt')
            with open(text_file_path, 'w') as file:
                file.write(f"This is decoy text file number {i}. It appears to contain important information.")

    def create_image_files(self):
        for i in range(self.number_of_files):
            image_file_path = os.path.join(self.documents_folder, f'decoy_image_{i}.png')
            image = Image.new('RGB', (100, 100), color='gray')
            image.save(image_file_path)



class FileMonitor(FileSystemEventHandler): # 해쉬값
    def __init__(self, directory):
        self.directory = directory
        self.file_hashes = {}
        self.observer = Observer()  # Observer 인스턴스 초기화

    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            logging.info(f"{file_path} 파일이 이동되거나 삭제되었습니다.")
            return None
        
    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            new_hash = self.calculate_hash(event.src_path)
            old_hash = self.file_hashes.get(event.src_path)
            if old_hash != new_hash:
                logging.info(f"{event.src_path} 파일이 변경되었습니다. 이전 해시: {old_hash}, 새 해시: {new_hash}")
            self.file_hashes[event.src_path] = new_hash


    def initial_scan(self):
        for root, dirs, files in os.walk(self.directory):
            for filename in files:
                file_path = os.path.join(root, filename)
                self.file_hashes[file_path] = self.calculate_hash(file_path)

    def start_monitoring(self):
        self.initial_scan()  # 초기 디렉토리 스캔
        self.observer.schedule(self, self.directory, recursive=True)
        self.observer.start()
        while True:
            time.sleep(1)       
    

class RansomwareAnalyzer: # 랜섬웨어 api 후킹
    def __init__(self):
        self.process = None
        self.change_hash  = {}  

    #exe파일 찾기
    def find_executable_files(self,directory):
        executable_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.exe'):  # 확장자가 .exe인 파일 찾기
                    executable_path = os.path.join(root, file)
                    print(executable_path)
                    executable_files.append(executable_path)
        return executable_files 

   #타겟 프로세스 자동 실행
    def spawn_ransomware(self, ransomware_path):
        try:
            self.pid = frida.spawn([ransomware_path])
            logging.info(f"랜섬웨어 실행, PID: {self.pid}")
        except Exception as e:
            logging.error(f"랜섬웨어 실행 실패: {e}")
            sys.exit(1)

    def attach_frida(self):
        with open(HOOKSCPATH, "r", encoding="utf-8") as js_file:
            js_script = js_file.read()

        try:
            self.session = frida.attach(self.pid)
            self.session.enable_child_gating()
            self.script = self.session.create_script(js_script)
            self.script.on('message', self.on_message)
            self.script.load()
            time.sleep(1)
            frida.resume(self.pid)  # 프로세스 실행 재개
        except frida.ProcessNotFoundError:
            logging.error("프로세스를 찾을 수 없습니다. 프로세스가 이미 종료되었을 수 있습니다.")
            sys.exit(1)
        except frida.NotSupportedError:
            logging.error("Frida가 이 프로세스에 붙을 수 없습니다. 보안제한을 확인하세요.")
            sys.exit(1)

    def analyze(self, RANSOMWAREPATH):
        executable_files = self.find_executable_files(RANSOMWAREPATH)
        if not executable_files:
            logging.error("실행 파일을 찾을 수 없습니다.")
            return
        self.filepath = os.path.abspath(executable_files[0])
        self.spawn_ransomware(self.filepath)  # 랜섬웨어를 spawn 모드로 실행
        self.attach_frida()  # Frida로 분석 시작
 
    #수신기
    def on_message(self, message, data):
        if message.get('type') == 'send' and 'payload' in message:
            payload = message['payload']
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError as e:
                    logging.error(f"payload변환 실패: {e}")
            logging.info(f"message:{payload}")


    # 정리 작업
    def cleanup(self):
        # 프로세스가 실행 중이라면 종료하고 프리다 세션 해제
        if self.process and self.process.poll() is None:  # 프로세스가 아직 실행 중인지 확인
            self.process.terminate()  # 프로세스 종료 요청
            self.process.wait()  # 프로세스가 종료될 때까지 대기
   # 프로세스 상태 확인
        else: # 프로세스가 종료되었음
            logging.error("프로세스 이미 종료됨")

    # 프리다 세션 해제
        if hasattr(self, 'session'):  # 세션 객체가 존재하는지 확인
            try:
                self.session.detach()  # 프리다 세션 해제 시도
            except frida.InvalidOperationError as e:  # 세션이 이미 해제된 경우 예외 처리
                logging.error("프리다 세션 이미 해제됨: ", e)

if __name__ == "__main__":
    
    logging.basicConfig(filename=LOGPATH, level=logging.INFO, encoding="utf-8", format='%(asctime)s:%(levelname)s:%(message)s')
    decoy_creator = MakeDecoy(5)
    decoy_creator.create_text_files()  # 텍스트 파일 생성
    decoy_creator.create_image_files() # 이미지 파일 생성
    directory_to_monitor = DECOYPATHS  # 모니터링할 디렉토리 경로 설정
    file_monitor = FileMonitor(directory_to_monitor)
    analyzer = RansomwareAnalyzer()

    # 랜섬웨어 분석을 위한 스레드 생성 및 시작
    analyzer_thread = threading.Thread(target=lambda: analyzer.analyze(RANSOMWAREPATH))
    analyzer_thread.start()

    # 파일 모니터링을 위한 스레드 생성 및 시작
    file_monitor_thread = threading.Thread(target=file_monitor.start_monitoring)
    file_monitor_thread.start()

    try:
        # 스레드 상태를 체크
        while analyzer_thread.is_alive() or file_monitor_thread.is_alive():
            analyzer_thread.join(0.1)
            file_monitor_thread.join(0.1)
        
    except KeyboardInterrupt:
        logging.info("keyboardInterrupt")
    finally:
        file_monitor.observer.stop()
        file_monitor.observer.join()
        analyzer.cleanup()