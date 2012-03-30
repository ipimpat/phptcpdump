<?php

/**
 * Tcpdump
 * Execute tcpdump
 * Support: host, port and portrange primitives
 * 
 * requirements: tcpdump and ifdata * 
 * Install ubuntu: sudo apt-get -y install tcpdump moreutils
 * 
 * Note reading packets from a network interface
 * may require that you have special privileges.
 * Reading a saved packet file doesn't require special privileges.   
 *
 * @author Kim Henriksen <kh@ipimp.at>
 * @see http://www.tcpdump.org/tcpdump_man.html tcpdump
 * @see http://linux.die.net/man/1/ifdata ifdata
 * @license http://philsturgeon.co.uk/code/dbad-license DBAD License
 */
class tcpdump {

    /**
     * Tcpdump options
     * @var array 
     */
    private $_options = array();

    /**
     * Path to tcpdump executable
     * @var string 
     */
    private $_tcpdump_executable = "/usr/sbin/tcpdump";

    /**
     * Path to ifdata executable
     * @var type 
     */
    private $_ifdata_executable = "/usr/bin/ifdata";

    /**
     * Pcap filter expression filter
     * @var type 
     */
    private $_filter = "";

    /**
     * Set class parameters
     * 
     * @param string $tcpdump_executable path to tcpdump executable
     * @param string $ifdata_executable path to ifdata executable
     * @throws InvalidArgumentException 
     */
    public function __construct($tcpdump_executable = NULL, $ifdata_executable = NULL) {
        // Set path to tcpdump executable
        if (!is_null($tcpdump_executable)) {
            // Check that the file exists
            if (is_file($tcpdump_executable))
                $this->_tcpdump_executable = $tcpdump_executable;
            else
                throw new InvalidArgumentException(sprintf("no such executable: %s", $tcpdump_executable), E_USER_ERROR);
        }
        // Set path to tcpdump executable
        if (!is_null($ifdata_executable)) {
            // Check that the file exists
            if (is_file($ifdata_executable))
                $this->_ifdata_executable = $ifdata_executable;
            else
                throw new InvalidArgumentException(sprintf("no such executable: %s", $ifdata_executable));
        }
    }

    /**
     * Initialize class
     * 
     * Optionaly pass a array of tcpdump options
     * Values is not validate or escaped, so don't use for direct user input
     * w/o escape values first
     * 
     * @param array $init_options
     * @throws InvalidArgumentException 
     */
    public function init($init_options = null) {
        if (is_array($init_options))
            $this->_options = $init_options;
        else
            throw new InvalidArgumentException('Init method only accepts arrays');
    }

    /**
     * Set interface option
     * 
     * Listen on interface. If unspecified, tcpdump searches the system 
     * interface list for the lowest numbered, configured up interface 
     * (excluding loopback). Ties are broken by choosing the earliest match. 
     * 
     * On Linux systems with 2.2 or later kernels, an interface argument 
     * of ``any'' can be used to capture packets from all interfaces.
     *  
     * Note that captures on the ``any'' device 
     * will not be done in promiscuous mode.
     * 
     * @param string $interface
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setInterface($interface) {
        // Validate listen interface name
        if (preg_match("/^([\w]+)(\.([\w]+))?$/", $interface)) {
            // Check that the interface exists
            if (trim(shell_exec(sprintf('sudo ifdata -e %s && echo $?', escapeshellarg($interface)))) == '0')
                $this->_options['-i'] = $interface;
            else
                throw new InvalidArgumentException(sprintf("interface %s does not exist", $interface));
        } else {
            throw new InvalidArgumentException(sprintf("invalid interface name %s", $interface));
        }
        return $this;
    }

    /**
     * Set output file option
     * 
     * Write the raw packets to file
     * They can later be read with the setInputFile() option. 
     * 
     * Note the file must be a pcap file and have a pcap file extension
     * 
     * @see http://www.manpagez.com/man/5/pcap-savefile/ 
     * @param string $file
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setOutputFile($file) {
        // validate output path
        if (preg_match(";^/[^/]?$|^/[^/]([^/]|/[^/])*?[^/]$;", $file))
            $this->_options['-w'] = $file;
        else
            throw new InvalidArgumentException(sprintf("invalid output file: %s", $file));

        return $this;
    }

    /**
     * Set input file option
     * 
     * Read packets from file (which was created with the setOutputFile option)
     * 
     * Note the file must be a pcap file and have a pcap file extension
     * 
     * @see http://www.manpagez.com/man/5/pcap-savefile/ 
     * @param string $file
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setInputFile($file) {
        // Validate input path
        if (preg_match(";^/[^/]?$|^/[^/]([^/]|/[^/])*?[^/]$;", $file))
            $this->_options['-r'] = $file;
        else
            throw new InvalidArgumentException(sprintf("invalid input file: %s", $file));

        return $this;
    }

    /**
     * Set file size option
     * 
     * Before writing a raw packet to a savefile, 
     * check whether the file is currently larger than file_size and 
     * if so, close the current savefile and open a new one. 
     * 
     * Savefiles after the first savefile will have the name specified 
     * with the -w flag, with a number after it
     * starting at 1 and continuing upward. 
     * The units of file_size are millions of bytes 
     * (1,000,000 bytes, not 1,048,576 bytes). 
     * 
     * @param string $size specify size in megabytes (eg 100)
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setFileSize($size) {
        // Validate file size value
        if (preg_match("/^[0-9]+$/", $size))
            $this->_options['-C'] = $size;
        else
            throw new InvalidArgumentException(sprintf("invalid file size %s", $size));

        return $this;
    }

    /**
     * Set snap lenght option
     * 
     * Snarf snaplen bytes of data from each packet rather than the 
     * default of 65535 bytes. 
     * 
     * Packets truncated because of a limited snapshot are indicated 
     * in the output with ``[|proto]'',
     *  where proto is the name of the protocol level at which the truncation 
     * has occurred. Note that taking larger snapshots both increases the 
     * amount of time it takes to process packets and, effectively 
     * decreases the amount of packet buffering. 
     * This may cause packets to be lost. 
     * You should limit snaplen to the smallest number that will capture 
     * the protocol information you're interested in. Setting snaplen to 0 
     * sets it to the default of 65535, for backwards compatibility
     * with recent older versions of tcpdump. 
     * 
     * @param type $lenght 
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setSnapLen($lenght) {
        // Validate snap lenght value
        if (preg_match("/^[0-9]+$/", $lenght))
            $this->_options['-s'] = $lenght;
        else
            throw new InvalidArgumentException(sprintf("invalid snap lenght %s", $lenght));

        return $this;
    }

    /**
     * Set pcap filter expression
     * @see pcapFilterExpression
     * @param string $filter
     * @return \tcpdump
     * @throws InvalidArgumentException 
     */
    public function setExprFilter($filter) {
        // Validate expression filter value
        if (!empty($filter))
            $this->_filter = $filter;
        else
            throw new InvalidArgumentException("invalid filter, empty string");

        return $this;
    }

    /**
     * Compile tcpdump shell command
     * compile the tcpdump shell command ready for exeuction
     * 
     * the command string is automatically escaped
     * 
     * @param string $pcap_filter_expr
     * @return string
     * @throws InvalidArgumentException 
     */
    public function compileShellCoammnd() {
        // Validate pcap filter expression
        if (!empty($this->_filter)) {
            // Compile parameter string
            $param_str = "";
            foreach ($this->_options as $option => $value) {
                if (!is_null($value))
                    $param_str .= $option . " " . escapeshellarg($value) . " ";
                else
                    $param_str .= $option . " ";
            }
            // Return tcpdump shell command string
            return escapeshellcmd($this->_tcpdump_executable . " " . trim($param_str) . " " . escapeshellarg($this->_filter));
        } else {
            throw new InvalidArgumentException("pcap filter expression cannot be empty");
        }
    }

}

?>
