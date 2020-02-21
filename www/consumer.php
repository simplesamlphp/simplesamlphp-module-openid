<?php

// Find the authentication state
if (!array_key_exists('AuthState', $_REQUEST) || empty($_REQUEST['AuthState'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing mandatory parameter: AuthState');
}

$authState = $_REQUEST['AuthState'];
/** @psalm-var array $state */
$state = \SimpleSAML\Auth\State::loadState($authState, 'openid:init');
$sourceId = $state['openid:AuthId'];

/** @psalm-var \SimpleSAML\Module\openid\Auth\Source\OpenIDConsumer|null $authSource */
$authSource = \SimpleSAML\Auth\Source::getById($sourceId);
if ($authSource === null) {
    throw new \SimpleSAML\Error\BadRequest('Invalid AuthId \'' . $sourceId . '\' - not found.');
}

$error = null;
try {
    if (!empty($_GET['openid_url'])) {
        $authSource->doAuth($state, (string) $_GET['openid_url']);
    }
} catch (Exception $e) {
    $error = $e->getMessage();
}

$config = \SimpleSAML\Configuration::getInstance();
$t = new \SimpleSAML\XHTML\Template($config, 'openid:consumer.twig', 'openid');
$t->data['error'] = $error;
$t->data['AuthState'] = $authState;
$t->data['header'] = 'OpenID Login';
$t->data['autofocus'] = 'openid-identifier';
$t->send();
