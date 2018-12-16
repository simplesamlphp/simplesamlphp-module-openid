<?php

namespace SimpleSAML\Module\openid\Auth\Source;

use \SimpleSAML\Module\openid\Utils;
use \SimpleSAML\Module\openid\StateStore;
use \SimpleSAML\Module\openid\SessionStore;

/*
 * Disable strict error reporting, since the OpenID library
 * used is PHP4-compatible, and not PHP5 strict-standards compatible.
 */
Utils::maskErrors(E_STRICT);
if (defined('E_DEPRECATED')) {
    // PHP 5.3 also has E_DEPRECATED
    Utils::maskErrors(constant('E_DEPRECATED'));
}

// Add the OpenID library search path.
set_include_path(get_include_path() . PATH_SEPARATOR . dirname(dirname(dirname(dirname(dirname(dirname(__FILE__)))))) . '/lib');

require_once('Auth/OpenID/AX.php');
require_once('Auth/OpenID/SReg.php');
require_once('Auth/OpenID/Server.php');
require_once('Auth/OpenID/ServerRequest.php');

/**
 * Authentication module which acts as an OpenID Consumer
 *
 * @author Andreas Åkre Solberg, <andreas.solberg@uninett.no>, UNINETT AS.
 * @package SimpleSAMLphp
 */
class OpenIDConsumer extends \SimpleSAML\Auth\Source
{
    /**
     * Static openid target to use.
     *
     * @var string|NULL
     */
    private $target;

    /**
     * Custom realm to use.
     *
     * @var string|NULL
     */
    private $realm;

    /**
     * List of optional attributes.
     */
    private $optionalAttributes;
    private $optionalAXAttributes;


    /**
     * List of required attributes.
     */
    private $requiredAttributes;
    private $requiredAXAttributes;

    /**
     * Validate SReg responses.
     */
    private $validateSReg;

    /**
     * List of custom extension args
     */
    private $extensionArgs;

    /**
     * Prefer HTTP Redirect over HTML Form Redirection (POST)
     */
    private $preferHttpRedirect;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config)
    {
        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        $cfgParse = \SimpleSAML\Configuration::loadFromArray($config,
            'Authentication source ' . var_export($this->authId, true));

        $this->target = $cfgParse->getString('target', null);
        $this->realm = $cfgParse->getString('realm', null);

        $this->optionalAttributes = $cfgParse->getArray('attributes.optional', []);
        $this->requiredAttributes = $cfgParse->getArray('attributes.required', []);

        $this->optionalAXAttributes = $cfgParse->getArray('attributes.ax_optional', []);
        $this->requiredAXAttributes = $cfgParse->getArray('attributes.ax_required', []);

        $this->validateSReg = $cfgParse->getBoolean('sreg.validate', true);

        $this->extensionArgs = $cfgParse->getArray('extension.args', []);

        $this->preferHttpRedirect = $cfgParse->getBoolean('prefer_http_redirect', false);
    }


    /**
     * Initiate authentication. Redirecting the user to the consumer endpoint 
     * with a state Auth ID.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(array &$state)
    {
        $state['openid:AuthId'] = $this->authId;

        if ($this->target !== null) {
            /* We know our OpenID target URL. Skip the page where we ask for it. */
            $this->doAuth($state, $this->target);

            /* doAuth() never returns. */
            assert(false);
        }

        $id = \SimpleSAML\Auth\State::saveState($state, 'openid:init');

        $url = \SimpleSAML\Module::getModuleURL('openid/consumer.php');
        \SimpleSAML\Utils\HTTP::redirectTrustedURL($url, ['AuthState' => $id]);
    }


    /**
     * Retrieve the Auth_OpenID_Consumer instance.
     *
     * @param array &$state  The state array we are currently working with.
     * @return \Auth_OpenID_Consumer  The Auth_OpenID_Consumer instance.
     */
    private function getConsumer(array &$state)
    {
        $store = new StateStore($state);
        $session = new SessionStore();
        return new \Auth_OpenID_Consumer($store, $session);
    }


    /**
     * Retrieve the URL we should return to after successful authentication.
     *
     * @return string  The URL we should return to after successful authentication.
     */
    private function getReturnTo($stateId)
    {
        assert(is_string($stateId));

        return \SimpleSAML\Module::getModuleURL('openid/linkback.php', [
            'AuthState' => $stateId,
        ]);
    }


    /**
     * Retrieve the trust root for this openid site.
     *
     * @return string  The trust root.
     */
    private function getTrustRoot()
    {
        if (!empty($this->realm)) {
            return $this->realm;
        } else {
            return \SimpleSAML\Utils\HTTP::getSelfURLHost();
        }
    }


    /**
     * Send an authentication request to the OpenID provider.
     *
     * @param array &$state  The state array.
     * @param string $openid  The OpenID we should try to authenticate with.
     */
    public function doAuth(array &$state, $openid)
    {
        assert(is_string($openid));

        $stateId = \SimpleSAML\Auth\State::saveState($state, 'openid:auth');

        $consumer = $this->getConsumer($state);

        // Begin the OpenID authentication process.
        $auth_request = $consumer->begin($openid);

        // No auth request means we can't begin OpenID.
        if (!$auth_request) {
            throw new \SimpleSAML\Error\BadRequest('Not a valid OpenID: ' . var_export($openid, true));
        }

        $sreg_request = \Auth_OpenID_SRegRequest::build(
            $this->requiredAttributes,
            $this->optionalAttributes
        );

        if ($sreg_request) {
            $auth_request->addExtension($sreg_request);
        }

        // Create attribute request object
        $ax_attribute = [];

        foreach($this->requiredAXAttributes as $attr) {
            $ax_attribute[] = \Auth_OpenID_AX_AttrInfo::make($attr, 1, true);
        }

        foreach($this->optionalAXAttributes as $attr) {
            $ax_attribute[] = \Auth_OpenID_AX_AttrInfo::make($attr, 1, false);
        }

        if (count($ax_attribute) > 0) {

            // Create AX fetch request
            $ax_request = new \Auth_OpenID_AX_FetchRequest;

            // Add attributes to AX fetch request
            foreach($ax_attribute as $attr) {
                $ax_request->add($attr);
            }

            // Add AX fetch request to authentication request
            $auth_request->addExtension($ax_request);

        }

        foreach ($this->extensionArgs as $ext_ns => $ext_arg) {
            if (is_array($ext_arg)) {
                foreach($ext_arg as $ext_key => $ext_value) {
                    $auth_request->addExtensionArg($ext_ns, $ext_key, $ext_value);
                }
            }
        }

        // Redirect the user to the OpenID server for authentication.
        // Store the token for this authentication so we can verify the
        // response.

        // For OpenID 1, send a redirect.  For OpenID 2, use a Javascript form
        // to send a POST request to the server or use redirect if
        // prefer_http_redirect is enabled and redirect URL size
        // is less than 2049
        $should_send_redirect = $auth_request->shouldSendRedirect();
        if ($this->preferHttpRedirect || $should_send_redirect) {
            $redirect_url = $auth_request->redirectURL($this->getTrustRoot(), $this->getReturnTo($stateId));

            // If the redirect URL can't be built, display an error message.
            if (\Auth_OpenID::isFailure($redirect_url)) {
                throw new \SimpleSAML\Error\AuthSource($this->authId, 'Could not redirect to server: ' . var_export($redirect_url->message, true));
            }

            // For OpenID 2 failover to POST if redirect URL is longer than 2048
            if ($should_send_redirect || strlen($redirect_url) <= 2048) {
                \SimpleSAML\Utils\HTTP::redirectTrustedURL($redirect_url);
                assert(false);
            }
        }

        // Generate form markup and render it.
        $form_id = 'openid_message';
        $form_html = $auth_request->formMarkup($this->getTrustRoot(), $this->getReturnTo($stateId), false, ['id' => $form_id]);

        // Display an error if the form markup couldn't be generated; otherwise, render the HTML.
        if (\Auth_OpenID::isFailure($form_html)) {
            throw new \SimpleSAML\Error\AuthSource($this->authId, 'Could not redirect to server: ' . var_export($form_html->message, true));
        } else {
            echo '<html><head><title>OpenID transaction in progress</title></head>
                <body onload=\'document.getElementById("' . $form_id . '").submit()\'>' .
                $form_html . '</body></html>';
            exit;
        }
    }


    /**
     * Process an authentication response.
     *
     * @param array &$state  The state array.
     */
    public function postAuth(array &$state)
    {

        $consumer = $this->getConsumer($state);

        $return_to = \SimpleSAML\Utils\HTTP::getSelfURL();

        // Complete the authentication process using the server's
        // response.
        $response = $consumer->complete($return_to);

        // Check the response status.
        if ($response->status == \Auth_OpenID_CANCEL) {
            // This means the authentication was cancelled.
            throw new \SimpleSAML\Error\UserAborted();
        } else if ($response->status == \Auth_OpenID_FAILURE) {
            // Authentication failed; display the error message.
            throw new \SimpleSAML\Error\AuthSource($this->authId, 'Authentication failed: ' . var_export($response->message, true));
        } else if ($response->status != \Auth_OpenID_SUCCESS) {
            throw new \SimpleSAML\Error\AuthSource($this->authId, 'General error. Try again.');
        }

        // This means the authentication succeeded; extract the
        // identity URL and Simple Registration data (if it was
        // returned).
        $openid = $response->identity_url;

        $attributes = ['openid' => [$openid]];
        $attributes['openid.server_url'] = [$response->endpoint->server_url];

        if ($response->endpoint->canonicalID) {
            $attributes['openid.canonicalID'] = [$response->endpoint->canonicalID];
        }

        if ($response->endpoint->local_id) {
                $attributes['openid.local_id'] = [$response->endpoint->local_id];
        }

        $sreg_resp = \Auth_OpenID_SRegResponse::fromSuccessResponse($response, $this->validateSReg);
        $sregresponse = $sreg_resp->contents();

        if (is_array($sregresponse) && count($sregresponse) > 0) {
            $attributes['openid.sregkeys'] = array_keys($sregresponse);
            foreach ($sregresponse AS $sregkey => $sregvalue) {
                $attributes['openid.sreg.' . $sregkey] = [$sregvalue];
            }
        }

        // Get AX response information
        $ax = new \Auth_OpenID_AX_FetchResponse();
        $ax_resp = $ax->fromSuccessResponse($response);

        if (($ax_resp instanceof \Auth_OpenID_AX_FetchResponse) && (!empty($ax_resp->data))) {
            $axresponse = $ax_resp->data;

            $attributes['openid.axkeys'] = array_keys($axresponse);
            foreach ($axresponse AS $axkey => $axvalue) {
                if (preg_match("/^\w+:/",$axkey)) {
                    $attributes[$axkey] = (is_array($axvalue)) ? $axvalue : [$axvalue];
                } else {
                    \SimpleSAML\Logger::warning('Invalid attribute name in AX response: ' . var_export($axkey, true));
                }
            }
        }

        \SimpleSAML\Logger::debug('OpenID Returned Attributes: '. implode(", ",array_keys($attributes)));

        $state['Attributes'] = $attributes;
        \SimpleSAML\Auth\Source::completeAuth($state);
    }
}
