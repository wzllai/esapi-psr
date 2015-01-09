<?php
/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project.
 *
 * PHP version 5.2
 *
 * LICENSE: This source file is subject to the New BSD license.  You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 *
 * @category  OWASP
 * @package   ESAPI_Reference
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   SVN: $Id$
 * @link      http://www.owasp.org/index.php/ESAPI
 */

use \Wast\SecurityConfiguration;
use \Wast\Errors\EnterpriseSecurityException;
use \Wast\Errors\IntrusionException;
use \Wast\ESAPI;

/**
 * Require Test Helpers and SecurityConfiguration
 */
require_once dirname(__FILE__) . '/../testresources/TestHelpers.php';
//require_once dirname(__FILE__) . '/../../src/SecurityConfiguration.php';
require __DIR__ . "/../../../autoload.php";
//session_start();
/**
 * Test for the DefaultIntrusionDetector implementation of the IntrusionDetector
 * interface.  Please note that this test case expects a custom version of ESAPI.xml
 * which contains IntrusionDetector events designed for these tests.
 *
 * @category  OWASP
 * @package   ESAPI
 * @author    jah <jah@jahboite.co.uk>
 * @copyright 2009-2010 The OWASP Foundation
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD license
 * @version   Release: @package_version@
 * @link      http://www.owasp.org/index.php/ESAPI
 */
class IntrusionDetectorTest extends PHPUnit_Framework_TestCase
{

    private $_logFileLoc    = null;
    private $_logDateFormat = null;
    private $_restoreSecCon = null;


    /**
     * Constructor swaps the SecurityConfiguration currently in use with one which
     * contains custom IDS events designed specifically for this UnitTestCase.
     *
     * @return null
     */
    function __construct()
    {
        global $ESAPI;
        if (! isset($ESAPI)) {
            $ESAPI = new ESAPI(
                dirname(__FILE__) . '/../testresources/ESAPI.xml'
            );
        }
        $this->_restoreSecCon = ESAPI::getSecurityConfiguration();
        ESAPI::setSecurityConfiguration(null);
        // Use a custom properties file.
        $sc = ESAPI::getSecurityConfiguration(
            dirname(__FILE__) . '/../testresources/ESAPI_IDS_Tests.xml'
        );

        $this->_logFileLoc = getLogFileLoc();
        $this->_logDateFormat = $sc->getLogFileDateFormat();
    }


    /**
     * Destructor restores the original SecurityConfiguration.
     *
     * @return null
     */
    function __destruct()
    {
        ESAPI::setSecurityConfiguration($this->_restoreSecCon);
    }


    /**
     * Test to ensure that EnterpriseSecurityExceptions are automatically added
     * to the IntrusionDetector and that the IntrusionDetector logs the
     * exceptions logMessage.
     *
     * @return bool True on Pass.
     */
    function testExceptionAutoAdd()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $logMsg = 'testExceptionAutoAdd_';
        $logMsg .= getRandomAlphaNumString(32);
        new EnterpriseSecurityException(
            'user message - testExceptionAutoAdd', $logMsg
        );

        $m = 'Test attempts to detect exception log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $logMsg),
            $m
        );
    }


    /**
     * Test of addException method of class DefaultIntrusionDetector.
     *
     * @return bool True on Pass.
     */
    function testAddException()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $logMsg = 'testAddException_';
        $logMsg .= getRandomAlphaNumString(32);
        ESAPI::getIntrusionDetector()->addException(new Exception($logMsg));

        $m = 'Test attempts to detect exception log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected($this->_logFileLoc, $logMsg),
            $m
        );
    }


    /**
     * Test of addEvent method of DefaultIntrusionDetector.  This test checks
     * that a threshold exceeded message is logged and thus tests the addEvent,
     * addSecurityEvent and Event.increment methods and that takeSecurityAction
     * performs the 'log' action.
     *
     * @return bool True on Pass.
     */
    function testAddEvent()
    {
        if ($this->_logFileLoc === false) {
            $this->fail(
                'Cannot perform this test because the log file cannot be found.'
            );
        }

        $eventName = 'AddEventTest';
        $threshold = ESAPI::getSecurityConfiguration()->getQuota($eventName);
        $date = new DateTime;

        // add event
        ESAPI::getIntrusionDetector()->addEvent(
            $eventName,
            'This is a Test Event for IntrusionDetectorTest.'
        );

        $find = "User exceeded quota of {$threshold->count} " .
            "per {$threshold->interval} seconds for event {$eventName}." .
            sprintf(
                ' Taking the following %d action%s - ',
                count($threshold->actions),
                count($threshold->actions) > 1 ? 's' : ''
            )
            . implode(', ', $threshold->actions) . '.';
        $m = 'Test attempts to detect IntrusionDetector' .
            ' action log message in logfile - %s';
        $this->assertTrue(
            fileContainsExpected(
                $this->_logFileLoc, $find, $date, 5, $this->_logDateFormat
            ),
            $m
        );
    }

}
