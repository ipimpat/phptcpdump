<?php

require 'pcapFilterExpression.php';
$pcap_filter_expr = new pcapFilterExpression();


// Simple test
$pcap_filter_expr->init(); // Init class
$pcap_filter_expr->begin() 
        ->host('192.168.0.2')
        ->concate()
        ->port(5060)
        ->end();

// Echo the expression
echo $pcap_filter_expr->getPcapFilterExpressionString(). "\r\n";

// Port range
$pcap_filter_expr->init(); // Init class
$pcap_filter_expr->begin() 
        ->host('192.168.0.2')
        ->concate()
        ->port_range(5060, 5061)
        ->end();

// Echo the expression
echo $pcap_filter_expr->getPcapFilterExpressionString(). "\r\n";


// Two host test
$pcap_filter_expr->init(); // Init class
$pcap_filter_expr->begin() 
        ->host('192.168.0.2')
        ->alternate()
        ->host('192.168.0.3')
        ->group()
        ->concate()
        ->port(5060)
        ->end();

// Echo the expression
echo $pcap_filter_expr->getPcapFilterExpressionString() . "\r\n";


?>
