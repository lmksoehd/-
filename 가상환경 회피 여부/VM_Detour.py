''' window 환경에서 실행, 특정한 레지스트리 경로를 확인하여 가상 환경 탐지.
    작동 원리: 랜섬웨어에 감염된 파일은 자신이 지금 가상환경 내에 속해있는지 확인 하니 이걸 역으로 사용해 파일이 가상환경 
    탐지를 하고 있는걸 탐지해 걸러낸다.'''
    
import requests

def check_aws_environment():
    try:
        metadata_url = "http://169.254.169.254/latest/meta-data/instance-id"
        response = requests.get(metadata_url, timeout=0.1)
        
        if response.status_code == 200:
            print("AWS 환경 내에서 실행되고 있습니다.")
            return True
    except requests.exceptions.RequestException as e:
        
        # 요청에 실패한 경우 (네트워크 오류, 타임아웃 등)
        print("AWS 환경이 아니거나, 메타데이터 서비스에 접근할 수 없습니다.")
        return False

# AWS 환경 확인 함수 실행
check_aws_environment()


