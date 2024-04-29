import requests
from requests.exceptions import RequestException
import os
import psutil

#EC2 메타데이터 엔드포인트 접근 감지
def check_ec2_metadata_access():
    try:
        response = requests.get('http://169.254.169.254/latest/meta-data/', timeout=2)
        if response.status_code == 200:
            print("EC2 메타데이터 엔드포인트에 접근 가능.")
            return True
    except RequestException:
        pass
    print("EC2 메타데이터 엔드포인트에 접근 불가능.")
    return False

check_ec2_metadata_access()

# 환경 변수 검사
def check_environment_variables():
    suspicious_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
    for var in suspicious_vars:
        if var in os.environ:
            print(f"환경 변수 {var} 발견됨. EC2 환경일 가능성 있음.")
            return True
    print("환경 변수에서 EC2 관련 항목을 찾을 수 없음.")
    return False

check_environment_variables()

#파일 시스템 및 프로세스 모니터링
def check_running_processes():
    suspicious_processes = ['malware_process', 'suspicious_process']
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] in suspicious_processes:
            print(f"의심스러운 프로세스 {proc.info['name']} 발견됨.")
            return True
    print("의심스러운 프로세스가 실행 중이지 않음.")
    return False

check_running_processes()

'''네트워크 트래픽 감지는 파이썬 코드만으로는 구현이 어려울 수 있으며,
이를 위해 네트워크 패킷 분석 도구나 IDS/IPS 시스템과 같은 추가적인 도구를 사용해야 할 수 있음.'''