package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

const EXIT = "exit"

var pubKey []byte
var prvKey []byte

func main() {
	help()

out:
	for {
		var command string
		fmt.Scan(&command)

	cmd:
		switch command {
		case "help":
			help()
			break cmd
		case "1":
			createRSAKey()
			break cmd
		case "2":
			encrypt()
			break cmd
		case "3":
			decrypt()
			break cmd
		case "4":
			importPubKey()
			break cmd
		case "5":
			importPrvKey()
			break cmd
		case EXIT:
			break out
		default:
			fmt.Println("不存在的命令")
			break cmd
		}
	}

	for i := 0; i < 3; i++ {
		fmt.Printf("\r退出倒计时: %d", 3-i)
		time.Sleep(time.Second)
	}
	fmt.Println("\n退出.....")
}

func help() {
	fmt.Println("你可以输入以下命令:\n",
		"  help  帮助信息\n",
		"  1     生成 rsa 密钥对\n",
		"  2     加密文本内容，输出 base64 字符串\n",
		"  3     解密 base64 字符串\n",
		"  4     导入公钥文件或者字符串\n",
		"  5     导入私钥文件或者字符串\n",
		"  exit  退出")
}

func createRSAKey() {
	fmt.Println("请输入密钥对输出目录")
	var dir string
	fmt.Scan(&dir)
	if dir == EXIT {
		return
	}
	stat, err := os.Stat(dir)
	if err != nil {
		fmt.Println("输入地址目录异常, 请检查是否正确")
		return
	}
	if !stat.IsDir() {
		fmt.Println("输入地址不是一个目录, 请检查是否正确")
		return
	}

	var pubFileName = "pub.key"
	var prvFileName = "prv.key"
	prvKey, pubKey := GenRsaKey()
	os.WriteFile(path.Join(dir, pubFileName), pubKey, 0644)
	os.WriteFile(path.Join(dir, prvFileName), prvKey, 0644)

	fmt.Printf("已在目录 %s 下生成密钥对, 公钥文件名为: %s, 私钥文件名为: %s \n", dir, pubFileName, prvFileName)
}

func GenRsaKey() (prvkey, pubkey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

func importPubKey() {
	fmt.Println("请输入公钥文件完整地址或者公钥字符串")
	var filePath string
	fmt.Scan(&filePath)
	if filePath == EXIT {
		return
	}
	if strings.HasPrefix(filePath, "-----BEGIN PUBLIC KEY-----") {
		pubKey = []byte(filePath)
	} else {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println("公钥文件地址异常, 请检查是否正确")
			return
		}
		pubKey = content
	}
	fmt.Println("导入公钥成功")
}

func importPrvKey() {
	fmt.Println("请输入私钥文件完整地址或者私钥字符串")
	var filePath string
	fmt.Scan(&filePath)
	if filePath == EXIT {
		return
	}
	if strings.HasPrefix(filePath, "-----BEGIN RSA PRIVATE KEY-----") {
		prvKey = []byte(filePath)
	} else {
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Println("私钥文件地址异常, 请检查是否正确")
			return
		}
		prvKey = content
	}
	fmt.Println("导入私钥成功")
}

func encrypt() {
	if pubKey == nil {
		fmt.Println("请先导入公钥")
		return
	}
	fmt.Println("请输入要加密的文本")
	var text string
	fmt.Scan(&text)
	if text == EXIT {
		return
	}

	data, err := rsaEncrypt([]byte(text), pubKey)
	if err != nil {
		fmt.Println("加密失败", err)
		return
	}
	fmt.Println("加密成功, 内容如下:")
	fmt.Println(base64.StdEncoding.EncodeToString(data))
}

func decrypt() {
	if pubKey == nil {
		fmt.Println("请先导入私钥")
		return
	}
	fmt.Println("请输入要解密的 base64 字符串")
	var text string
	fmt.Scan(&text)
	if text == EXIT {
		return
	}

	decodeBase64, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fmt.Println("解码 base64 字符串失败, 请检查输入是否正确")
		return
	}
	data, err := rsaDecrypt(decodeBase64, prvKey)
	if err != nil {
		fmt.Println("解密失败", err)
		return
	}
	fmt.Println("解密成功, 内容如下:")
	fmt.Println(string(data))
}

func rsaEncrypt(data, keyBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("公钥解析失败")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func rsaDecrypt(ciphertext, keyBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("私钥解析失败")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	data, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	return data, nil
}
