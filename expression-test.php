<?php

require 'pcapFilterExpression.php';
$expr = new pcapFilterExpression();


// Simple test
try {
    // initialize class
    $expr->init();
    // compile expression
    $expr->begin()
            ->host('192.168.0.2')
            ->concate()
            ->port(5060)
            ->end();
    // Echo the expression
    echo $expr->getPcapFilterExpressionString() . "\r\n";
} catch (InvalidArgumentException $e) {
    trigger_error($e->getMessage(), E_USER_ERROR);
} catch (Exception $e) {
    echo $e->getMessage();
}

// Port range test
try {
    // initialize class
    $expr->init();
    // compile expression
    $expr->begin()
            ->host('192.168.0.2')
            ->concate()
            ->port_range(5060, 5061)
            ->end();
    // Echo the expression
    echo $expr->getPcapFilterExpressionString() . "\r\n";
} catch (InvalidArgumentException $e) {
    trigger_error($e->getMessage(), E_USER_ERROR);
} catch (Exception $e) {
    echo $e->getMessage();
}

// Two host test
try {
    // initialize class
    $expr->init();
    // compile expression
    $expr->begin()
            ->host('192.168.0.2')
            ->alternate()
            ->host('192.168.0.3')
            ->group()
            ->concate()
            ->port(5060)
            ->end();
    // Echo the expression
    echo $expr->getPcapFilterExpressionString() . "\r\n";
} catch (Exception $e) {
    echo $e->getMessage();
} catch (InvalidArgumentException $e) {
    trigger_error($e->getMessage(), E_USER_ERROR);
} catch (Exception $e) {
    echo $e->getMessage();
}
?>
