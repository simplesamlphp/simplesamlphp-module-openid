<?php

// Find the authentication state
if (!array_key_exists('AuthState', $_REQUEST) || empty($_REQUEST['AuthState'])) {
    throw new \SimpleSAML\Error\BadRequest('Missing mandatory parameter: AuthState');
}
$state = \SimpleSAML\Auth\State::loadState($_REQUEST['AuthState'], 'openid:auth');
$sourceId = $state['openid:AuthId'];
$authSource = \SimpleSAML\Auth\Source::getById($sourceId);
if ($authSource === null) {
    throw new \SimpleSAML\Error\BadRequest('Invalid AuthId \'' . $sourceId . '\' - not found.');
}

try {
    $authSource->postAuth($state);
    // postAuth() should never return.
    assert(false);
} catch (\SimpleSAML\Error\Exception $e) {
    \SimpleSAML\Auth\State::throwException($state, $e);
} catch (\Exception $e) {
    \SimpleSAML\Auth\State::throwException(
        $state,
        new \SimpleSAML\Error\AuthSource($sourceId, 'Error on OpenID linkback endpoint.', $e)
    );
}
