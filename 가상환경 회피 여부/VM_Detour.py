''' window 환경에서 실행, 특정한 레지스트리 경로를 확인하여 가상 환경 탐지.
    작동 원리: 랜섬웨어에 감염된 파일은 자신이 지금 가상환경 내에 속해있는지 확인 하니 이걸 역으로 사용해 파일이 가상환경 
    탐지를 하고 있는걸 탐지해 걸러낸다.
    즉, 아마존 서버 내에서 비정상적인 파일이 자신이 가상서버 내에 존재하는지 검사하는 것을 탐지하고 싶다
    이것을 위해선 네트워크 트래픽을 모니터링하거나, 시스템 호출을 감시하는 방법을 사용할 수 있음'''
    
import requests

def check_metadata_access():
    try:
        response = requests.get("http://169.254.169.254/latest/meta-data/")
        if response.status_code == 200:
            print("Access to EC2 instance metadata detected.")
        else:
            print("Failed to access EC2 instance metadata.")
    except Exception as e:
        print("Error accessing EC2 instance metadata: ", e)

check_metadata_access()



