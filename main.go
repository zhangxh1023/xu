package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"strconv"
	"time"
	"unsafe"
)

const EXIT = "exit"
const CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+=-@#~,.[]()!%^*$"

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
			importPubKey()
			break cmd
		case "3":
			importPrvKey()
			break cmd
		case "4":
			encryptText()
			break cmd
		case "5":
			decryptText()
			break cmd
		case "6":
			encryptFile()
			break cmd
		case "7":
			decryptFile()
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
		"  2     导入公钥文件\n",
		"  3     导入私钥文件\n",
		"  4     加密文本内容，输出 base64 字符串\n",
		"  5     解密 base64 字符串\n",
		"  6     加密文件\n",
		"  7     解密文件\n",
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
	prvKey, pubKey := genRSAKey()
	os.WriteFile(path.Join(dir, pubFileName), pubKey, 0644)
	os.WriteFile(path.Join(dir, prvFileName), prvKey, 0644)

	fmt.Printf("已在目录 %s 下生成密钥对, 公钥文件名为: %s, 私钥文件名为: %s \n", dir, pubFileName, prvFileName)
}

func genRSAKey() (prvkey, pubkey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
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
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("公钥文件地址异常, 请检查是否正确")
		return
	}
	pubKey = content
	fmt.Println("导入公钥成功")
}

func importPrvKey() {
	fmt.Println("请输入私钥文件完整地址或者私钥字符串")
	var filePath string
	fmt.Scan(&filePath)
	if filePath == EXIT {
		return
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("私钥文件地址异常, 请检查是否正确")
		return
	}
	prvKey = content
	fmt.Println("导入私钥成功")
}

func encryptText() {
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

	data, err := rsaEncrypt([]byte(text))
	if err != nil {
		fmt.Println("加密失败", err)
		return
	}
	fmt.Println("加密成功, 内容如下:")
	fmt.Println(base64.StdEncoding.EncodeToString(data))
}

func decryptText() {
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
	data, err := rsaDecrypt(decodeBase64)
	if err != nil {
		fmt.Println("解密失败", err)
		return
	}
	fmt.Println("解密成功, 内容如下:")
	fmt.Println(string(data))
}

func rsaEncrypt(data []byte) ([]byte, error) {
	block, _ := pem.Decode(pubKey)
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

func rsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
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

func genAESKey() ([]byte, error) {
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(CHARACTERS))))
		if err != nil {
			return nil, err
		}
		key[i] = CHARACTERS[n.Int64()]
	}
	return key, nil
}

func encryptFile() {
	if pubKey == nil {
		fmt.Println("请先导入公钥")
		return
	}
	fmt.Println("请输入要加密的文件地址")
	var inputPath string
	fmt.Scan(&inputPath)
	inputStat, err := os.Stat(inputPath)
	if err != nil {
		fmt.Println("文件地址异常, 请检查输入是否正确")
		return
	}
	if inputStat.IsDir() {
		fmt.Println("目标地址不是一个文件, 请检查输入是否正确")
		return
	}
	fmt.Println("请输入要输出的文件地址")
	var outputPath string
	fmt.Scan(&outputPath)
	_, err = os.Stat(outputPath)
	if err == nil {
		fmt.Println("文件地址异常, 请检查输入是否正确")
		return
	}

	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Println("读取文件失败")
		return
	}
	enFileData, err := encryptFileData(fileData, inputStat.Name())
	if err != nil {
		fmt.Println("加密文件失败")
		return
	}
	err = os.WriteFile(outputPath, enFileData, 0644)
	if err != nil {
		fmt.Println("写入文件失败")
		return
	}
	fmt.Printf("加密文件成功, 文件地址: %s\n", outputPath)
}

func decryptFile() {
	if prvKey == nil {
		fmt.Println("请先导入私钥")
		return
	}
	fmt.Println("请输入要解密的文件地址")
	var inputPath string
	fmt.Scan(&inputPath)
	inputStat, err := os.Stat(inputPath)
	if err != nil {
		fmt.Println("文件地址异常, 请检查输入是否正确")
		return
	}
	if inputStat.IsDir() {
		fmt.Println("目标地址不是一个文件, 请检查输入是否正确")
		return
	}
	fmt.Println("请输入解密后输出文件的目录")
	var outputPath string
	fmt.Scan(&outputPath)
	stat, err := os.Stat(outputPath)
	if err != nil || !stat.IsDir() {
		fmt.Println("目录地址异常, 请检查输入是否正确")
		return
	}

	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Println("读取文件失败")
		return
	}
	deFileData, filename, err := decryptFileData(fileData)
	if err != nil {
		fmt.Println("解密文件失败")
		return
	}
	err = os.WriteFile(path.Join(outputPath, filename), deFileData, 0644)
	if err != nil {
		fmt.Println("写入文件失败")
	}
	fmt.Printf("解密文件成功, 文件地址: %s\n", path.Join(outputPath, filename))
}

func decryptFileData(fileData []byte) ([]byte, string, error) {
	curr := 0
	aeskeySizeByte := make([]byte, strconv.IntSize/8)
	for i := 0; i < len(aeskeySizeByte); i++ {
		aeskeySizeByte[i] = fileData[curr+i]
	}
	curr += len(aeskeySizeByte)
	aeskeySize := byteArrayToInt(aeskeySizeByte)
	aesKeyEnByte := make([]byte, aeskeySize)
	for i := 0; i < len(aesKeyEnByte); i++ {
		aesKeyEnByte[i] = fileData[curr+i]
	}
	curr += len(aesKeyEnByte)
	aesKeyByte, err := rsaDecrypt(aesKeyEnByte)
	if err != nil {
		return nil, "", err
	}
	filenameSizeByte := make([]byte, strconv.IntSize/8)
	for i := 0; i < len(filenameSizeByte); i++ {
		filenameSizeByte[i] = fileData[curr+i]
	}
	curr += len(filenameSizeByte)
	filenameSize := byteArrayToInt(filenameSizeByte)
	filenameEnByte := make([]byte, filenameSize)
	for i := 0; i < len(filenameEnByte); i++ {
		filenameEnByte[i] = fileData[curr+i]
	}
	curr += len(filenameEnByte)
	filenameByte, err := rsaDecrypt(filenameEnByte)
	if err != nil {
		return nil, "", err
	}
	fileDataEnByte := make([]byte, len(fileData)-curr)
	for i := 0; i < len(fileDataEnByte); i++ {
		fileDataEnByte[i] = fileData[curr+i]
	}
	curr += len(fileDataEnByte)
	deFileData, err := aesDecrypt(fileDataEnByte, aesKeyByte)
	if err != nil {
		return nil, "", err
	}
	return deFileData, string(filenameByte), nil
}

func encryptFileData(fileData []byte, filename string) ([]byte, error) {
	aesKey, err := genAESKey()
	if err != nil {
		return nil, err
	}
	fmt.Println(len(aesKey))
	encryptAESKey, err := rsaEncrypt(aesKey)
	if err != nil {
		return nil, err
	}
	encryptFilename, err := rsaEncrypt([]byte(filename))
	if err != nil {
		return nil, err
	}
	enFileData, err := aesEncrypt(fileData, aesKey)
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	buffer.Write(intToByteArray(len(encryptAESKey)))
	buffer.Write(encryptAESKey)
	buffer.Write(intToByteArray(len(encryptFilename)))
	buffer.Write(encryptFilename)
	buffer.Write(enFileData)
	return buffer.Bytes(), nil
}

func intToByteArray(num int) []byte {
	size := int(unsafe.Sizeof(num))
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}

func byteArrayToInt(arr []byte) int {
	val := int(0)
	size := len(arr)
	for i := 0; i < size; i++ {
		*(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&val)) + uintptr(i))) = arr[i]
	}
	return val
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = pkcs7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pkcs7UnPadding(origData)
	return origData, nil
}
