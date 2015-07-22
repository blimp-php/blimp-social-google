<?php
namespace Blimp\Accounts\Rest;

use Blimp\Accounts\Documents\Account;
use Blimp\Http\BlimpHttpException;
use Blimp\Accounts\Oauth2\Oauth2AccessToken;
use Blimp\Accounts\Oauth2\Protocol;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class GoogleAccessToken extends Oauth2AccessToken {
    public function getAuthorizationEndpoint() {
        return 'https://accounts.google.com/o/oauth2/auth';
    }

    public function getAccessTokenEndpoint() {
        return 'https://www.googleapis.com/oauth2/v3/token';
    }

    public function getClientID() {
        return $this->api['config']['google']['client_id'];
    }

    public function getClientSecret() {
        return $this->api['config']['google']['client_secret'];
    }

    public function getScope() {
        return $this->api['config']['google']['scope'];
    }

    public function getDisplay() {
        return $this->request->query->get('display') != NULL ? $this->request->query->get('display') : 'popup';
    }

    public function getOtherAuthorizationRequestParams() {
        $redirect_url = '';

        $display = $this->getDisplay();
        if ($display != null && strlen($display) > 0) {
            $redirect_url .= '&display=' << $display;
        }

        if ($this->getForceLogin()) {
            $redirect_url .= '&auth_type=reauthenticate';
        }

        return $redirect_url;
    }

    public function processAccountData($access_token) {
        if ($access_token != NULL) {
            $token = $access_token['token'];
            
            /* Get profile_data */
            $params = [
                'access_token' => $token,
                'fields' => $this->api['config']['google']['fields']
            ];

            $profile_data = Protocol::get('https://www.googleapis.com/userinfo/v2/me', $params);

            if($profile_data instanceof Response) {
                return $profile_data;
            }

            if ($profile_data != null && $profile_data['id'] != null) {
                if(!empty($access_token['account']) && $profile_data['email'] != $access_token['account']) {
                    throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, "Invalid access_token");
                }
                
                $id = hash_hmac('ripemd160', 'google-' . $profile_data['id'], 'obscure');

                $dm = $this->api['dataaccess.mongoodm.documentmanager']();

                $account = $dm->find('Blimp\Accounts\Documents\Account', $id);

                if ($account != null) {
                    $code = Response::HTTP_FOUND;
                } else {
                    $code = Response::HTTP_CREATED;
                    
                    $account = new Account();
                    $account->setId($id);
                    $account->setType('google');
                }

                $resource_uri = '/accounts/' . $account->getId();
                
                $secret = NULL;
                if($account->getOwner() == NULL) {
                    $bytes = openssl_random_pseudo_bytes(16);
                    $hex   = bin2hex($bytes);
                    $secret = password_hash($hex, PASSWORD_DEFAULT);                
                }

                $account->setBlimpSecret($secret);
                $account->setAuthData($access_token);
                $account->setProfileData($profile_data);
                
                $dm->persist($account);
                $dm->flush();

                $response = new JsonResponse((object) ["uri" => $resource_uri, "secret" => $secret], $code);
                $response->headers->set('AccountUri', $resource_uri);
                $response->headers->set('AccountSecret', $secret);

                return $response;
            } else {
                throw new BlimpHttpException(Response::HTTP_NOT_FOUND, "Resource not found");
            }
        } else {
            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, "No access_token");
        }
    }
}
