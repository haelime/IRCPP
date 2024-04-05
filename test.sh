make re

# IRC 서버 실행 함수
run_irc_server() {
    ./ircserv 6667 1234 &
}

# 테스트 메시지
TEST[0]='PASS 1234'
TEST[1]='NICK hae'
TEST[2]='USER haeLoginName 0 * :haeRealname'
TEST[3]='JOIN #haeChannel channelPassword'
TEST[4]='MODE #haeChannel +sn'
TEST[5]='TOPIC #haeChannel :For test!'
TEST[6]='PRIVMSG #haeChannel :Hello, server!'
TEST[7]='PART #haeChannel :Bye, channel!'
TEST[8]='QUIT awsd :Bye,server!'
TEST[9]='PRIVATE hae :AM I STILL HERE?'

# 서버 실행
run_irc_server

# 잠시 대기하여 서버가 준비될 때까지 기다립니다.
sleep 3

# 서버 IP와 포트 설정
SERVER_IP="127.0.0.1"
SERVER_PORT="6667"

# 서버에 메시지 보내기

# 테스트 메시지 전송
(
    # to every test message
    for ((i=0; i<${#TEST[@]}; i++))
    do
        printf "%s\r\n" "${TEST[$i]}"
        sleep 1                                                                                                                                                                                                                                                        
    done
    ) | nc $SERVER_IP $SERVER_PORT | cat > IrcClient.log

printf "\n"
printf "Test Client Log\n"
printf "======================================\n"
cat IrcClient.log
printf "======================================\n"

# 서버 종료 확인
if pgrep -x "ircserv" > /dev/null
then
    echo "IRC Tested Successfully"
    pkill -x ircserv
    exit 0
else
    echo "IRC Server Failed to Run"
    exit 1
fi
