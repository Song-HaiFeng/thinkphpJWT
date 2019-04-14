<?php
namespace app\index\controller;

class Index extends AdminControl
{

	public function _initialize()
    {
        parent::_initialize();
    }

   	// 有token才可以访问
   	public function getAuth()
   	{
   		$data = $this -> getUserInfo();
   		return json(['data' => $data, 'message' => 'success', 'code' => 200]);
   	}

   	// 刷新access_token
   	public function refreshToken()
   	{
   		return $this -> checkToken();
   	}

   	// 获取用户资料并获取token
   	public function getUserInfoAndGetToken()
   	{
   		// 用户资料
   		$user = [
   			'ID' => 6,
   			'username' => 'XiaoFeng',
   			'avatar' => 'https://www.songhaifeng.com/zb_users/theme/Lucky/style/image/touxiang.png',
   			'state' => 1,
   		];

   		// 获取access_token
   		$access_token = $this -> getToken($user);

   		// 获取refresh_token
   		$refresh_token = $this -> getToken($user, true);

   		// 返回数据
   		return json([
			'data' => [
				'access_token' => $access_token,
				'refresh_token' => $refresh_token
			],
			'message' => 'success',
			'code' => 200
   		]);

   	}

}
