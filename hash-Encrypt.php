<?php

use includes_hash_encrypt_1020 as HashEncrypt;

/**
 * 随机、hash函数、加解密等
 * 
 * 数组加密: decryptArray()
 * 数组解密: authcodeArray()
 * 字符串加密: decrypt()
 * 字符串解密: authcode()
 * 
 * Development: 2021.10.20
 * updateTime： 2022.07.28
 * Version: 2.0
 */

class includes_hash_encrypt_1020 {
    
    private static $chars = 'pqrstuklmnovwDEFGxyz1234ABCHIOPQRSTUVWXYZabcdeJKLMNfghij56789';
    private static $common_chars = 'abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWYXZ';

    /**
     * 数组加密
     * @param $token 需要加密码原值
     * @return string
     */
    public static function decryptArray($token) {

        $token = serialize($token);
        return self::decrypt($token);
    }

    /**
     * 数组解密
     * @param $token 需要解密值
     * @return mixed
     */
    public static function authcodeArray( $token ){
        $token = self::authcode($token);
        return unserialize($token);
    }

    /**
     * 检验token是否正确(解密)
     * @param $token 需要验证的值
     * @param $dongle 加密狗  默认 chars
     * @return false|string
     */
    public static function authcode($token = '', $dongle = 'chars'){

        if (empty($token)) return false;


        switch ($dongle) {
            case 'chars' :
                $chars = self::$chars;
                break;

            case 'common':
                $chars = self::$common_chars;
                break;

            default:
                $chars = $dongle;
                break;
        }

        /** 第一次解密 先反转 */

        $ch = substr($token, -1);
        $nh = strpos($chars, $ch); //基数第一次出现的位置
        $token = substr($token, 0, -1);

        $before = substr($token, 0, $nh);
        $after  = substr($token, $nh);
        $token = $after.$before;

        /** 第一次解密 结束 */

        $ch = $token[0]; //token第一位做为基数
        $nh = strpos($chars, $ch); //基数第一次出现的位置
        $mdKey = md5(substr($chars, $nh)); //$chars字符串（$nh基数位置）的后面所有字符串并转换成md5
        $mdKey = self::base64Encode($mdKey); //把MD5转换成 base64

        //替换字符串中的一些字符（str_ireplace: 不区分大小写）
        //替换字符串中的一些字符（str_replace: 区分大小写）
        $token = str_replace($mdKey, '', $token); //替换字符串
        $txt = substr($token, 1); //删除第一位基数
        $tmp = trim(base64_decode($txt)); //base64解密

        $obstruct = explode("//////", $tmp); //删除token的干扰数
        if (count($obstruct) > 1) {
            $tmp = $obstruct[1];
        }
        return $tmp;


    }

    /**
     * 加密规则
     * @param $token 需要验证的值
     * @param $dongle 加密狗  默认 chars
     * @param $obstruct 加密干扰
     * @return string
     */
    public static function decrypt( $token = '', $dongle = 'chars', $obstruct = true ){

        switch ( $dongle ){
            case 'chars' :
                $chars = self::$chars;
                break;
                
            case 'common':
                $chars = self::$common_chars;
                break;
                
            default:
                $chars = $dongle;
                break;
        }

        if( empty($token) ){
            $token = time(); //获取当前时间
        }

        $nh = strlen( $chars ) - 1; //随机数统计
        $tmp_nh = mt_rand(0, $nh); //随机数
        $ch = $chars[$tmp_nh]; //取chars第N位做为基数

        $mdKey = md5( substr($chars, $tmp_nh) ); //$chars字符串（$nh基数位置）的后面所有字符串并转换成md5

        $Key = self::base64Encode($mdKey); //把MD5转换成 base64

        if($obstruct){
            $token = uniqid() . '//////' . $token . '//////' . md5(uniqid()); //增加token的干扰性
        }

        $txt = self::base64Encode($token); //base64加密

        $key1 = $ch . substr($txt, 0, $tmp_nh) . $Key . substr($txt, $tmp_nh); //完成第一次加密码

        /** 第二次反转加密 */
        $tmp_nh = mt_rand(0, $nh); //随机数
        (int)$KeyStatistics = strlen( $key1 );
        $ch1 = $chars[$tmp_nh]; //取chars第N位做为基数

        return substr($key1, $tmp_nh * (-1)) . substr($key1, 0, $KeyStatistics - $tmp_nh) . $ch1;

    }

    /**
     * 转换成 base64
     * @param $data
     * @return false|string|string[]
     */
    private static function base64Encode($data){
        if(empty($data)) return false;

        $Key = base64_encode($data); //把MD5转换成
        return str_replace('=', '', $Key);
    }


}
