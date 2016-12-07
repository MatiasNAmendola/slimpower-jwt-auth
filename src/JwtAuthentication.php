<?php

/**
 * This file is part of Slim JSON Web Token Authentication middleware
 *
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5.3
 *
 * @category    Authentication
 * @package     SlimPower
 * @subpackage  JwtAuthentication
 * @author      Matias Nahuel Améndola <soporte.esolutions@gmail.com>
 * @link        https://github.com/matiasnamendola/slimpower-jwt-auth
 * @license     http://www.opensource.org/licenses/mit-license.html MIT License
 * @copyright   2016
 * 
 * MIT LICENSE
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace SlimPower\JwtAuthentication;

use SlimPower\Authentication\AbstractAuthentication;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SlimPower\JWT\JWT;

class JwtAuthentication extends AbstractAuthentication {

    protected $logger;

    protected function setOptions($options = array()) {
        parent::setOptions($options);

        $base = array(
            "cookie" => "token",
            "secret" => "secret"
        );

        $this->options = array_replace_recursive($base, $this->options);
    }

    protected function customValidation() {
        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($this->data)) {
            return false;
        } else {
            $this->data['decoded'] = $decoded;

            /* Everything ok, add custom property! */
            $this->app->jwtenc = $this->data['token'];

            return true;
        }
    }

    /**
     * Get Params
     * @return array Params
     */
    protected function getParams() {
        $params = array("decoded" => $this->data['decoded'], "app" => $this->app);
        return $params;
    }

    /**
     * Fetch the access token
     *
     * @return string|false Base64 encoded JSON Web Token or false if not found.
     */
    public function fetchData() {
        /* If using PHP in CGI mode and non standard environment */
        if (isset($_SERVER[$this->options["environment"]])) {
            $message = "Using token from environent";
            $header = $_SERVER[$this->options["environment"]];
        } else {
            $message = "Using token from request header";
            $header = $this->app->request->headers("Authorization");
        }

        $matches = null;

        if (preg_match("/Bearer\s+(.*)$/i", $header, $matches)) {
            $this->log(LogLevel::DEBUG, $message);
            return $matches[1];
        }

        /* Bearer not found, try a cookie. */
        if ($this->app->getCookie($this->options["cookie"])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            $token = $this->app->getCookie($this->options["cookie"]);
            return array('token' => $token);
        }

        /* If everything fails log and return false. */
        $this->message = "Token not found";
        $this->log(LogLevel::WARNING, $this->message);
        return false;
    }

    public function decodeToken($token) {
        try {
            return JWT::decode(
                            $token, $this->options["secret"], array("HS256", "HS512", "HS384", "RS256")
            );
        } catch (\Exception $exception) {
            $this->message = $exception->getMessage();
            $this->log(LogLevel::WARNING, $exception->getMessage(), array($token));
            return false;
        }
    }

    /**
     * Get the cookie name where to search the token from
     *
     * @return string
     */
    public function getCookie() {
        return $this->options["cookie"];
    }

    /**
     * Set the cookie name where to search the token from
     *
     * @return self
     */
    public function setCookie($cookie) {
        $this->options["cookie"] = $cookie;
        return $this;
    }

    /**
     * Get the secret key
     *
     * @return string
     */
    public function getSecret() {
        return $this->options["secret"];
    }

    /**
     * Set the secret key
     *
     * @return self
     */
    public function setSecret($secret) {
        $this->options["secret"] = $secret;
        return $this;
    }

    /* Cannot use traits since PHP 5.3 should be supported */

    /**
     * Get the logger
     *
     * @return Psr\Log\LoggerInterface $logger
     */
    public function getLogger() {
        return $this->logger;
    }

    /**
     * Set the logger
     *
     * @param Psr\Log\LoggerInterface $logger
     * @return self
     */
    public function setLogger(LoggerInterface $logger = null) {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed  $level
     * @param string $message
     * @param array  $context
     *
     * @return null
     */
    public function log($level, $message, array $context = array()) {
        if ($this->logger) {
            return $this->logger->log($level, $message, $context);
        }
    }

}
