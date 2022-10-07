package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"time"
)

var (
	timeout      int64
	size         int
	count        int
	sendCount    int
	successCount int
	failCount    int
	minTs        int64 = math.MaxInt32
	maxTs        int64 = math.MinInt32
	totalTs      int64
)

const (
	ICMP_ECHO_REQUEST_TYPE = 8
	ICMP_ECHO_REQUEST_CODE = 0
	//ICMP_ECHO_REPLY_TYPE   = 0
	//ICMP_ECHO_REPLY_CODE   = 0
)

type ICMPHeader struct {
	Type        uint8
	Code        uint8
	CheckSum    uint16
	ID          uint16
	SequenceNum uint16
}

func main() {
	// ping基于ICMP协议，ICMP报文封装在IP数据报内部
	// IP固定首部20字节
	// ICMP首部8字节

	getCommandArgs()
	destinationIP := os.Args[len(os.Args)-1]
	conn, err := net.DialTimeout("ip:icmp", destinationIP, time.Duration(timeout)*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Printf("正在 Ping %s [%s] 具有 %d 字节的数据:\n", destinationIP, conn.RemoteAddr(), size)

	for i := 0; i < count; i++ {
		sendCount++
		start := time.Now()
		icmpHeader := &ICMPHeader{
			Type:        ICMP_ECHO_REQUEST_TYPE,
			Code:        ICMP_ECHO_REQUEST_CODE,
			CheckSum:    0,
			ID:          1,
			SequenceNum: 1,
		}

		data := make([]byte, size)
		var buffer bytes.Buffer
		binary.Write(&buffer, binary.BigEndian, icmpHeader) // 缓冲区中写入头部信息，指定大端存放
		buffer.Write(data)                                  // 缓冲区写入内容
		icmpMessage := buffer.Bytes()                       // 获取缓冲区未读部分，即整个icmp报文

		checkSum := checkSum(icmpMessage)
		icmpMessage[2], icmpMessage[3] = byte(checkSum>>8), byte(checkSum)          // 校验和存放与前面相同，也要为大端存放
		conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond)) // 设置读写超时时间
		_, err := conn.Write(icmpMessage)                                           // 发送ping请求
		if err != nil {
			failCount++
			log.Println(err)
			continue
		}
		buf := make([]byte, 65535)
		_, err = conn.Read(buf) // 读取ip数据报
		if err != nil {
			failCount++
			log.Println(err)
			continue
		}

		//fmt.Println(n, buf)
		// todo TCP/IP协议规定了在网络上必须采用网络字节顺序，先收到的字节为高位，最后收到的字节为低位，也就是大端模式。
		// 	解析ip头部信息
		//version := buf[0] >> 4 // 4位 协议版本 IPv4为4，IPv6为6
		//fmt.Println("version:", version)
		//headerLength := buf[0] & 0x0F // 4位 头部长度（单位字节），最小为5，最大为15
		//fmt.Println("headerLength:", headerLength)
		//serviceType := buf[1] // 8位 服务
		//fmt.Println("serviceType:", serviceType)
		//totalLength := uint16(buf[2])<<8 + uint16(buf[3]) // 16位 整个IP数据报的长度（单位字节），包括协议头部和数据。其最大值为65535字节
		//fmt.Println("totalLength:", totalLength)
		ttl := buf[8]
		//fmt.Println("ttl:", ttl)
		//protocol := buf[9]
		//fmt.Println(protocol)
		//headerCheckSum := uint16(buf[10])<<8 + uint16(buf[11])
		//fmt.Println(headerCheckSum)
		sourceIP := fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15])
		consumeTs := time.Since(start).Milliseconds()
		if consumeTs < minTs {
			minTs = consumeTs
		}
		if consumeTs > maxTs {
			maxTs = consumeTs
		}
		totalTs += consumeTs
		fmt.Printf("来自 %s 的回复: 字节=%d 时间=%dms TTL=%d\n", sourceIP, size, consumeTs, ttl)
		successCount++
	}

	fmt.Printf("%s 的 Ping 统计信息:\n", conn.RemoteAddr())
	fmt.Printf("    数据包: 已发送 = %d，已接收 = %d，丢失 = %d (%.2f%% 丢失)，\n", sendCount, successCount, failCount, float64(failCount)/float64(sendCount))
	fmt.Printf("往返行程的估计时间(以毫秒为单位):\n")
	fmt.Printf("    最短 = %dms，最长 = %dms，平均 = %dms", minTs, maxTs, totalTs/int64(sendCount))

}

func getCommandArgs() {
	// 读取控制台指令
	flag.Int64Var(&timeout, "w", 1000, "请求超时时长，单位毫秒")
	flag.IntVar(&size, "l", 32, "请求发送缓冲区大小，单位字节")
	flag.IntVar(&count, "n", 4, "发送请求数")
	flag.Parse()
}

func checkSum(data []byte) uint16 {
	// ICMP校验算法 todo
	// 1.先将校验和置为0，
	// 2.然后将ICMP报文的header+body按16bit分组求和(若长度为奇数，则将剩余的1个字节，也累加到求和)。
	// 3.如果结果溢出，则将高16位和低16位求和，直到高16位为0。
	// 4.最后求反就是检验和的值。

	// 1.校验和置0
	data[2], data[3] = 0, 0

	// 2.将ICMP报文的header+body按16bit分组求和
	length := len(data)
	index := 0
	var sum uint32
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	// 若长度为奇数，则将剩余的1个字节，也累加到求和
	if length != 0 {
		sum += uint32(data[index])
	}
	// 3.如果结果溢出，则将高16位和低16位求和，直到高16位为0
	high16 := sum >> 16
	for high16 != 0 {
		sum = high16 + uint32(uint16(sum))
		high16 = sum >> 16
	}
	// 4.最后求反就是检验和的值
	return uint16(^sum)
}
