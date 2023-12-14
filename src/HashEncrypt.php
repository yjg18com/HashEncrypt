<?php
/**
 * Notes: 一套简单php加密/解密算法方案
 * User: darcy
 * Author: 252452324@qq.com
 * Date: 2023/12/12
 * Time: 10:57
 * Version: v1.0.5
 */

namespace DarcySdk\Util;


class HashEncrypt
{
    // 加密的常用字符串做为公钥，可能做为加密串使用（注意，字符串不能有重复）
    protected string $_access = 'abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWYXZ';

    // 加密解密私钥
    protected string $_secre = '';

    //签名类型
    protected string $_signType;


    /**
     * 配置初始构造函数
     *
     * @param string $secreKey 加密密钥
     * @param string $signType 签名类型
     * @param string $accessKey 加密公钥
     */
    public function __construct(string $secreKey = '', string $signType = 'sha1', string $accessKey = '')
    {
        $accessKey = $accessKey ?: $this->_access;

        //过滤字符串中的重复字符
        $this->_access = implode('', array_unique(str_split($accessKey)));

        //私钥
        $this->_secre = $secreKey ?: $this->_secre;

        //签名类型
        $this->_signType = $signType;
    }


    /**
     * 加密
     * @param $plainText 明文
     * @return string
     */
    public function encrypt($plainText = ''): string
    {
        if (empty($plainText)) return '';

        //如果是标量转换成序列化
        if (is_array($plainText) || is_object($plainText)) {
            $plainText = serialize($plainText);
        }

        $chars = $this->_access;

        $nh = strlen( $chars ) - 1; //随机数统计
        $tmp_nh = random_int(0, $nh); //随机数
        $ch = $chars[$tmp_nh]; //取chars第N位做为基数

        $Key = $this->createSign(substr($chars, $tmp_nh)); //$chars字符串（$nh基数位置）的后面所有字符串并转换成 密钥
        $txt = $this->getBase64Encode($plainText); //明文转成 base64

        /** 第一次算法加密及反转 */
        $content1 = $tmp_nh == 0 ? '' : substr($txt, 0, $tmp_nh);
        $content2 = strrev(substr($txt, $tmp_nh));
        $key1 = $ch . $content1 . $Key . $content2; //数据拼接

        /** 第二次算法加密及反转 */
        $tmp_nh = random_int(0, $nh); //随机数
        $KeyStatistics = strlen($key1);
        $ch1 = $chars[$tmp_nh]; //取chars第N位做为基数
        $content_1 = $tmp_nh == 0 ? '' : strrev(substr($key1, $tmp_nh * (-1))); //切割后面内容并反转
        $content_2 = substr($key1, 0, $KeyStatistics - $tmp_nh);

        return $this->getBase64Encode($content_1 . $content_2 . $ch1);
    }


    /**
     * 解密
     * @param string $cipherText 密文
     * @return string|array|object
     */
    public function decrypt(string $cipherText = '')
    {
        if (empty($cipherText)) return '';


        // 字符串是否为Base64编码
        if (!base64_decode($cipherText, true) === false) {
            $cipherText = base64_decode($cipherText);
        }

        $chars = $this->_access;

        /** 第一次解密 先反转 */
        $ch = substr($cipherText, -1); //取最后一位做为基数
        $nh = strpos($chars, $ch); //基数第一次出现的位置
        $content = substr($cipherText, 0, -1);

        $before = strrev(substr($content, 0, $nh));
        $after = substr($content, $nh);
        $content = $after . $before; //第一次解密数据拼接


        /** 第二次解密 */
        $ch = $content[0]; //token第一位做为基数
        $nh = strpos($chars, $ch); //基数第一次出现的位置
        $mdKey = $this->createSign(substr($chars, $nh)); //生成对比密钥
        $content = substr($content, 1); //删除第一位基数

        $contentAres = explode($mdKey, $content); //拆分数据
        $content_1 = array_shift($contentAres); //第一部分

        $txt = $content_1 . strrev(implode('', $contentAres)); //数据拼接

        $content = trim(base64_decode($txt)); //base64解码

        // Base64解码检测字符的编码
        if (mb_detect_encoding($content, mb_detect_order(), true) === false) return 'Invalid Ciphertext';

        if($this->is_serialized($content)){
            $content = unserialize($content); //反序列化
        }

        return $content;
    }


    /**
     * 创建密钥
     * @param string $str 内容
     * @return string
     */
    private function createSign(string $str = ''): string
    {
        $signType = strtolower($this->_signType);

        if (in_array($signType, hash_algos())) {
            $hashVar = hash($signType, $str . $this->_secre); //散列
        } else {
            $hashVar = bin2hex(md5($signType) . $str . $this->_secre); //转换为十六进制
        }

        return $this->getBase64Encode($hashVar);
    }


    /**
     * 转换成 base64
     * @param string $str 内容
     * @return string
     */
    private function getBase64Encode(string $str = ''):string
    {
        if(empty($str)) return '';

        $str = \base64_encode($str);
        return str_replace('=', '', $str);
    }


    /**
     * 检查值以确定它是否已序列化
     * 如果 $data 不是字符串，则返回值将始终为 false
     * 序列化数据始终是字符串
     *
     * @param string $data  用于检查是否已序列化的值
     * @return bool
     */
    private function is_serialized($data):bool
    {
        // 检查是否为序列化的数据
        if (is_string($data)) {

            $data = trim($data);

            if ('N;' == $data) {
                return true;
            }

            if (!preg_match('/^([adObis]):/', $data, $badions)) {
                return false;
            }

            switch ($badions[1]) {
                case 'a':
                case 'O':
                case 's':
                    if (preg_match("/^{$badions[1]}:[0-9]+:.*[;}]\$/s", $data)) {
                        return true;
                    }
                    break;
                case 'b':
                case 'i':
                case 'd':
                    if (preg_match("/^{$badions[1]}:[0-9.E-]+;\$/", $data)) {
                        return true;
                    }
                    break;
            }
        }
        return false;
    }



}