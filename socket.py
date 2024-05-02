#server
import socket
from _thread import * #서버에 접속하는 클라이언트 마다 스레드 추가하기 위한 모듈 가져오기

client_socket = [] #create that saving client socket information List

#define thread() : 클라이언트가 떠날 때 까지 채널 관리
def thread(client_socket, addr) :
    print (f'>> Connected by : {addr[0]:addr[1]}')
    
    #클라이언트 연결 종료시까지 반복 수행
    while True:
        try: # received respond send by client(echo)
            data = client_socket.recv(1204)

            if not data:
                print(f'>> disconnected by {addr[0]:addr[1]} ')
                break
            print(f'>> received from {addr[0]:addr[1]} \n {data.decode()}')

            # send message to connected client
            client_socket.send(data)
            
        except ConnectionResetError as e :
            print(f'>> disconnected by {addr[0]:addr[1]}')
            break

    client_socket.close()
            


#sever information
HOST = '127.0.0.1' #socket.gethostbyname() 서버 아이피 주소 찾기 함수
PORT = 2024

#create socket
print(f'>> Server start with ip {HOST}')
server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#socket.SOCK_STREAM=> TCP 방식 사용(ipv4)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)#SO_REUSEADDR 주소 재사용이 중요

#bind()
server_socket.bind(HOST,PORT) # ip주소와 port 로 통신 할 수 있도록 묶어주기


#listen () 연결 요청 클라이언트 접근 요청에 수신 대기열
server_socket.listen()

# accept
try:
    while True:
        print('>> wait')# listen 상테에서 accept 할 수 있는 상태임
        client_socket, addr = server_socket.accept()#클라이언트 접속
        start_new_thread(thread, (client_socket, addr))#create thread

except Exception as e:# 소켓 api 에서 어느 에러인지 알아서 {e} 부분에 출력
    print('error:{e}')

finally:
    
# 소멸
server_socket.close()
