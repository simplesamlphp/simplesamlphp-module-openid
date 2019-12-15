<?php

namespace SimpleSAML\Module\openid;

/**
 * Class which implements the openid session store logic.
 *
 * This class has the interface specified in the constructor of the
 * Auth_OpenID_Consumer class.
 *
 * @package SimpleSAMLphp
 */
class SessionStore
{
    /**
     * Retrieve a key from the session store.
     *
     * @param string $key  The key we should retrieve.
     * @return mixed  The value stored with the given key, or NULL if the key isn't found.
     */
    public function get(string $key)
    {
        $session = \SimpleSAML\Session::getSessionFromRequest();
        return $session->getData('openid.session', $key);
    }


    /**
     * Save a value to the session store under the given key.
     *
     * @param string $key  The key we should save.
     * @param mixed|NULL $value  The value we should save.
     */
    public function set(string $key, $value)
    {
        $session = \SimpleSAML\Session::getSessionFromRequest();
        $session->setData('openid.session', $key, $value);
    }


    /**
     * Delete a key from the session store.
     *
     * @param string $key  The key we should delete.
     */
    public function del(string $key): void
    {
        $session = \SimpleSAML\Session::getSessionFromRequest();
        $session->deleteData('openid.session', $key);
    }
}
