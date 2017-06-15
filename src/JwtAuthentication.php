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

use SlimPower\Authentication\Abstracts\TokenAuthMiddleware;
use SlimPower\JWT\JWT;

class JwtAuthentication extends TokenAuthMiddleware {

    protected $logger;

    protected function setOptions($options = array()) {
        parent::setOptions($options);

        $base = array(
            "secret" => "secret"
        );

        $this->options = array_replace_recursive($base, $this->options);
    }

    public function decodeToken($token, &$details) {
        $details = '';
        $allowedAlgs = array("HS256", "HS512", "HS384", "RS256");

        try {
            return JWT::decode($token, $this->options["secret"], $allowedAlgs);
        } catch (\Exception $exception) {
            $details = $exception->getMessage();
            return false;
        }
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

}
