<?php
include("framework.php");
if (!defined("STDIN")) define("STDIN", fopen("php://stdin", "r"));
ini_set('display_errors', FALSE);
$framework = new framework();
function _LOG($text, $lvl=0)
{
	global $framework;
	return $framework->log($text, $lvl);
}

function usage()
{
	$banner = "
	------------------------------------
	Blind SQL Injection Framework ".BSIFW_VERSION."
	------------------------------------
	";
	$list = 
	array(
		array("cmd" => "",		"parameters" => "",		"description" => "\t\t* --------- Target --------- *"),
		array("cmd" => "host",		"parameters" => "<host> (port)", "description" => "set the hostname and port to attack"),
		array("cmd" => "path", 		"parameters" => "<path> (rest)", "description" => "set the path to the script with rest behind it"),
		array("cmd" => "",		"parameters" => "",		"description" => "\t\t* --------- Attack --------- *"),
		array("cmd" => "method", 	"parameters" => "<id>", 	"description" => "\tmethod to use"),
		array("cmd" => "space",		"parameters" => "<string>",	"description" => "\tuse <string> as space in query"),
		array("cmd" => "end",		"parameters" => "<string>",	"description" => "\tuse <string> as end string in query"),
		array("cmd" => "length",	"parameters" => "<length>", 	"description" => "\tuse max <length> characters in charset"),
		array("cmd" => "",		"parameters" => "",		"description" => "\t\t* --------- Query --------- *"),
		array("cmd" => "interval",	"parameters" => "<interval>",	"description" => "wait <interval> milliseconds before next try"),
		array("cmd" => "attack",	"parameters" => "<type> <params>","description" => "execute query <type> on target"),
		array("cmd" => "",		"parameters" => "",		"description" => "\t\t* ---------- Results ---------- *"),
		array("cmd" => "show",		"parameters" => "",		"description" => "\t\tshow gathered info"),
		array("cmd" => "cache",		"parameters" => "",		"description" => "\t\tshow all cached entries"),
		array("cmd" => "",		"parameters" => "",		"description" => "\t\t* ------------------------------------------*"),
		array("cmd" => "debug",		"parameters" => "<level>",	"description" => "\tset debug to <level>"),
		array("cmd" => "help",		"parameters" => "",		"description" => "\t\tshow usage"),
		array("cmd" => "cls",		"parameters" => "",		"description" => "\t\tclear screen"),
		array("cmd" => "quit",		"parameters" => "",		"description" => "\t\tquit this shell")
	);
	_LOG($banner);
	_LOG("Usage:");
	for ($i=0; $i<count($list); $i++)
	{
		_LOG("\t".$list[$i]["cmd"]." ".$list[$i]["parameters"]."\t".$list[$i]["description"]."\r\n");
	}
}

usage();
$hfile = $framework->getFileHandle();
while(1)
{
	print("\r\nshell>");
	$line = fgets(STDIN);
	$line = trim($line);
	$argv = split(" ", $line);
	fwrite($hfile, "\r\nshell>$line\r\n");
	$argc = count($argv);
	switch($argv[0])
	{
		case "host":
		{
			$host = $framework->getHost();
			$port = $framework->getPort();
			if ($argc < 2)
			{
				_LOG("host <host> (port)");
				_LOG("Current host: $host:$port");
				break;
			}
			$_host = $argv[1];
			$_port = ($argc > 2 ? intval($argv[2]) : 80);
			if (!$framework->setHost($_host, $_port))
				_LOG("[-] Error: ".$framework->getError());
			else
				_LOG("[*] Host set to $_host:$_port");
		}
		break;

		case "path":
		{
			$path = $framework->getPath();
			$rest = $framework->getRest();
			if ($argc < 2)
			{
				_LOG("path <path>");
				_LOG("Current path: $path$rest");
				break;
			}
			$_path = $argv[1];
			$_rest = ($argc > 2 ? $argv[2] : null);
			if (!$framework->setPath($_path, $_rest))
				_LOG("[-] Error: ".$framework->getError());
			else
				_LOG("[*] Changed path from $path to $_path\r\n[*] Rest from $rest to $_rest");
		}
		break;

		case "method":
		{
			if ($argc < 3)
			{
				_LOG("method <id> <params>");
				for ($i=0; $i<count($framework->methods); $i++)
					_LOG("\t".$framework->methods[$i]["id"]." ".$framework->methods[$i]["params"]."\t".$framework->methods[$i]["descr"]);
				_LOG("Current method: ".$framework->getMethod());
				break;
			}
			$params = null;
			for ($i=0; $i<$argc-2; $i++)
			{
				$params[$i] = $argv[$i+2];
			}
			$old = $framework->getMethod();
			if (!$framework->setMethod($argv[1], $params))
				_LOG("[-] Error: ".$framework->getError());
			else
				_LOG("[*] Changed method id from $old to ".$argv[1]);
		}
		break;

		case "space":
		{
			_LOG("[*] Changed space from ".$framework->space." to ".$argv[1]);
			$framework->space = $argv[1];
		}
		break;

		case "end":
		{
			_LOG("[*] Changed end from ".$framework->end." to ".$argv[1]);
			$framework->end = $argv[1];
		}
		break;

		case "length":
		{
			if ($argc < 2)
			{
				_LOG("length <length>");
				_LOG("Current length: ".$framework->getCharlen());
				break;
			}
			_LOG("[*] Changed length from ".$framework->getCharlen()." to ".$argv[1]);
			$framework->setCharlen($argv[1]);
		}
		break;

		case "interval":
		{
			if ($argc < 2)
			{
				_LOG("interval <milliseconds>");
				_LOG("Current interval: ".$framework->getInterval());
				break;
			}
			_LOG("[*] Changed interval from ".$framework->getInterval()." to ".intval($argv[1])." milliseconds");
			$framework->setInterval(intval($argv[1]));
		}
		break;

		case "attack":
		{
			if ($argc < 2)
			{
				_LOG("attack <query> (params)");
				for ($i=0; $i<count($framework->qtypes); $i++)
					_LOG("\t".$framework->qtypes[$i]["type"]." ".$framework->qtypes[$i]["params"]."\t".$framework->qtypes[$i]["descr"]);
				_LOG("Current query: ".$framework->qtype);
				break;
			}
			$framework->qtype = intval($argv[1]);
			$params = array();
			for ($i=0; $i<$argc-2; $i++)
			{
				$params[$i] = $argv[$i+2];
			}
			$start = time();
			if (!$framework->start($params))
			{
				_LOG("[-] Error: ".$framework->getError());
				break;
			}
			$end = time();
			_LOG("[*] Attack took ".($end-$start)." second(s)");
		}
		break;

		case "show":
		{
			$framework->show_database_info();
		}
		break;

		case "cache":
		{
			$framework->show_cache_list(0);
		}
		break;

		case "debug":
		{
			if ($argc < 2)
			{
				_LOG("debug <level>");
				_LOG("Current debug level: ".$framework->debug);
				break;
			}
			$debug = intval($argv[1]);
			_LOG("[*] Changed debug from level ".$framework->debug." to $debug");
			$framework->debug = $debug;
		}
		break;

		case "help":
		{
			usage();
		}
		break;

		// Standard commands, optional
		case "cls":
		{
			for ($i=0; $i<300; $i++) print("\r\n");
		}
		break;

		case "quit":
		{
			_LOG("[*] Exiting...");
			exit();
		}
		break;

		default:
		{
			_LOG("'".$argv[0]."' is not reconized as a valid option.");
		}
		break;
	}
}
?>
