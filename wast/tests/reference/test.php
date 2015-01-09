<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - 2009 The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Andrew van der Stock (vanderaj @ owasp.org)
 * @created 2009
 * @since 1.6
 */
 
//require_once dirname(__FILE__).'/../../src/ESAPI.php';
//require_once dirname(__FILE__).'/../../src/reference/RandomAccessReferenceMap.php';

use \Wast\ESAPI;
use \Wast\Reference\RandomAccessReferenceMap; 
use \Wast\Errors\AccessControlException;

require __DIR__ . "/../../../autoload.php";

class RandomAccessReferenceMapTest extends PHPUnit_Framework_TestCase 
{
    function setUp() 
    {
        global $ESAPI;
        
        if ( !isset($ESAPI)) 
        {
            $ESAPI = new ESAPI();
        }
    }
    
    function tearDown()
    {
        
    }
    /**
     * Test of getDirectReference method, of class
     * org.owasp.esapi.AccessReferenceMap.
     * 
     * @throws AccessControlException
     *             the access control exception
     */
    function testGetDirectReference()  
    {
        $directReference = "234";
        
        $directArray = array();
        $directArray[] = "123";
        $directArray[] = $directReference;
        $directArray[] = "345";
        print_r($directArray);
        $instance = new RandomAccessReferenceMap( $directArray );
        
        $ind = $instance->getIndirectReference($directReference);
        $dir = $instance->getDirectReference($ind);
        
        // echo "<p>ind = [$ind], dir = [$dir], directreference = [$directReference]";
        
        $this->assertEquals($directReference, $dir);
        try 
        {
            $instance->getDirectReference("invalid");
            $this->fail();
        }
        catch ( AccessControlException $e ) 
        {
            // success
        }
    }
    
}
?>
