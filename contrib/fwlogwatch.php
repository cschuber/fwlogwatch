<?
/* $Id: fwlogwatch.php,v 1.3 2003/04/08 21:43:05 bwess Exp $ */

/*
  This program is a rewrite based on work by

  Kyle Amon
  amonk@backwatcher.com
  BackWatcher, Inc.
  www.backwatcher.com

  released under the terms of the GNU General Public License.
*/

$debug = '0';
$logdir = "/var/log";
$logbase = messages;
$fwlogwatch = "/usr/local/sbin/fwlogwatch";

/**********************************************************************/

if (!$view) {
  $view = "list_files";
}

echo "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n";
echo "<html>\n";
echo "<head>\n";
echo "  <title>fwlogwatch web reporting module</title>\n";
echo "</head>\n";
echo "<body>\n";
$view();
echo "</body>\n";
echo "</html>\n";


function list_files() {
  global $logdir, $logbase;

  echo "<table width=\"100%\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "<tr>\n";
  echo "  <td>File</td>\n";
  echo "  <td>Date</td>\n";
  echo "  <td>Size</td>\n";
  echo "  <td>Actions</td>\n";
  echo "</tr>\n";
  $dirhandle=opendir($logdir);
  while (false!==($logfile = readdir($dirhandle))) {
    $abs_logpath = $logdir . "/" . $logfile;
    if (ereg("^$logbase.*", $logfile)) {
      if (is_file($abs_logpath)) {
        $mtime = filemtime($abs_logpath);
        $stamp = date("D, d M Y H:i:s", $mtime);
        $size = filesize($abs_logpath);
        $exp = 1;
        while($size >= pow(1024, $exp)) {
          $exp++;
        }
        $ext = array(" B", " K", " M", " G", " T");
        $summary = round(($size * 100) / pow(1024, ($exp - 1))) / 100;
        $strsize = sprintf("%.2f%s", $summary, $ext[$exp - 1]);
        echo "<tr>\n";
        echo "  <td>$logfile</td>\n";
        echo "  <td>$stamp</td>\n";
        echo "  <td>$strsize</td>\n";
        echo "  <td>\n";
        echo "    <a href=\"$PHP_SELF?view=show&amp;logfile=$logfile\">Show</a> / \n";
        echo "    <a href=\"$PHP_SELF?view=report&amp;logfile=$logfile\">Report</a>\n";
        echo "  </td>\n";
        echo "</tr>\n";
      }
    }
  }
  echo "</table>\n";
  closedir($dirhandle);
}


function cut($dir_logfile, $start, $end, $total, $amount) {
  if(!$amount) {
    $amount = 25;
  }
  if($total) {
    if($start < 1) {
      $start = 1;
      $end = $start + $amount;
    }
    if($end > $total) {
      $end = $total;
      $start = $end - $amount;
    }
  }
  $fd = gzopen($dir_logfile, r);
  for($i = 0; $i < $start ; $i++) {
    $line = gzgets($fd, 4096);
    if(gzeof($fd) || !$line) {
      return;
    }
  }
  $j = 0;
  for(; $i < $end; $i++) {
    $line = gzgets($fd, 4096);
    if($line && !gzeof($fd)) {
      $out[$j++] = $line;
    } else {
      return $out;
    }
  }
  return $out;
}


function report() {
  global $debug, $logdir, $logfile, $HTTP_POST_VARS, $PHP_SELF, $fwlogwatch;

  extract($HTTP_POST_VARS);
  echo "<form method=\"post\" action=\"$PHP_SELF?view=report&amp;logfile=$logfile\">\n";
  echo "<table width=\"100%\" border=\"1\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "<tr>\n";
  echo "  <th>Options</th>\n";
  echo "  <th>Sorting</th>\n";
  echo "</tr>\n";
  echo "<tr>\n";
  echo "  <td>\n";
  echo "    <table width=\"100%\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <em>Description</em>\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <em>On/Off</em>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Source address\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"sourceip\" value=\"S\" checked>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Source port\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"sourceport\" value=\"s\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Destination address\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"destip\" value=\"D\" checked>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Destination port\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"destport\" value=\"d\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Protocol\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"proto\" value=\"p\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Start times\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"stimes\" value=\"t\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        End times\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"etimes\" value=\"e\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Time intervals\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"intervals\" value=\"z\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Byte counts\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"bytes\" value=\"b\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        TCP options\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"tcpopts\" value=\"y\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        DNS lookups\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"dns\" value=\"n\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Service lookups\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"checkbox\" name=\"slookup\" value=\"N\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Hide entries with count below:\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"text\" name=\"hide\" size=\"5\" maxlength=\"5\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Show only this many entries:\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"text\" name=\"top\" size=\"5\" maxlength=\"5\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Analyze entries at most this old:\n";
  echo "      </td>\n";
  echo "      <td align=\"center\">\n";
  echo "        <input type=\"text\" name=\"old\" size=\"5\" maxlength=\"5\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    </table>\n";
  echo "  </td>\n";
  echo "  <td valign=\"top\">\n";
  echo "    <table width=\"100%\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <em>On/Off</em>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <em>Description</em>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <em>Up/Down</em>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <em>Priority</em>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"S\" value=\"S\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Source address\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"Sdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"Sdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"Sorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"s\" value=\"s\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Source port\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"sdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"sdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"sorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"D\" value=\"D\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Destination address\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"Ddir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"Ddir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"Dorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"d\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Destination port\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"ddir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"ddir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"dorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"p\" value=\"p\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Protocol\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"pdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"pdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"porder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"t\" value=\"t\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Start time\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"tdir\" value=\"a\" checked>&nbsp;\n";
  echo "        <input type=\"radio\" name=\"tdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"torder\">\n";
  echo "          <option value=\"1\">1</option>\n";
  echo "          <option value=\"2\" selected=\"selected\">2</option>\n";
  for($count = 3 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"e\" value=\"e\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        End time\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"edir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"edir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"eorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"z\" value=\"z\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Time interval\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"zdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"zdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"zorder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"b\" value=\"b\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Byte count\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"bdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"bdir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"border\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"c\" value=\"c\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Count\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"cdir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"cdir\" value=\"d\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"corder\">\n";
  echo "          <option value=\"1\" selected=\"selected\">1</option>\n";
  for($count = 2 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"n\" value=\"n\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Target name\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"radio\" name=\"ndir\" value=\"a\">&nbsp;\n";
  echo "        <input type=\"radio\" name=\"ndir\" value=\"d\">\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <select name=\"norder\">\n";
  for($count = 1 ; $count <= 11 ; $count++) {
    echo "          <option value=\"$count\">$count</option>\n";
  }
  echo "        </select>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    </table>\n";
  echo "  </td>\n";
  echo "</tr>\n";
  echo "<tr>\n";
  echo "  <th colspan=\"2\">Parsers</th>\n";
  echo "</tr>\n";
  echo "<tr>\n";
  echo "  <td colspan=\"2\">\n";
  echo "    <table width=\"100%\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        ipchains\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsei\" value=\"i\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        NetScreen\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsee\" value=\"e\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        netfilter\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsen\" value=\"n\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Windows XP\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsew\" value=\"w\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        ipfilter\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsef\" value=\"f\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Elsa Lancom\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsel\" value=\"l\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Cisco IOS\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsec\" value=\"c\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        Snort\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parses\" value=\"s\">\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    <tr>\n";
  echo "      <td>\n";
  echo "        Cisco PIX\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "        <input type=\"checkbox\" name=\"parsep\" value=\"p\" checked>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "      </td>\n";
  echo "      <td>\n";
  echo "      </td>\n";
  echo "    </tr>\n";
  echo "    </table>\n";
  echo "  </td>\n";
  echo "</tr>\n";
  echo "<tr>\n";
  echo "  <th colspan=\"2\">\n";
  echo "    <input type=\"submit\" name=\"report\" value=\"Apply\">\n";
  echo "    <input type=\"reset\" value=\"Reset to defaults\">\n";
  echo "    <a href=\"$PHP_SELF\">Back to file overview</a> / \n";
  echo "    <a href=\"$PHP_SELF?view=show&amp;logfile=$logfile\">View the log directly</a>\n";
  echo "  </th>\n";
  echo "</tr>\n";
  echo "<tr>\n";
  echo "  <td colspan=\"2\">\n";

  if(!$report) {
    $sorting = 'cd';
  } else {
    if ($sourceip) $sourceip = ''; else $sourceip ='S';
    if ($destip) $destip = ''; else $destip ='D';
    $selectivity = "$sourceip$sourceport$destip$destport$proto$stimes$etimes$intervals$bytes$tcpopts$dns$slookup";
    $joined[0] = ($order[0] = $corder).($criterion[0] = $c).($dir[c] = $cdir);
    $joined[1] = ($order[1] = $torder).($criterion[1] = $t).($dir[t] = $tdir);
    $joined[2] = ($order[2] = $zorder).($criterion[2] = $z).($dir[z] = $zdir);
    $joined[3] = ($order[3] = $norder).($criterion[3] = $n).($dir[n] = $ndir);
    $joined[4] = ($order[4] = $porder).($criterion[4] = $p).($dir[p] = $pdir);
    $joined[5] = ($order[5] = $border).($criterion[5] = $b).($dir[b] = $bdir);
    $joined[6] = ($order[6] = $Sorder).($criterion[6] = $S).($dir[S] = $Sdir);
    $joined[7] = ($order[7] = $sorder).($criterion[7] = $s).($dir[s] = $sdir);
    $joined[8] = ($order[8] = $Dorder).($criterion[8] = $D).($dir[D] = $Ddir);
    $joined[9] = ($order[9] = $dorder).($criterion[9] = $d).($dir[d] = $ddir);
    $joined[10] = ($order[10] = $eorder).($criterion[10] = $e).($dir[e] = $edir);
    if($debug) {
      echo "<pre>\n";
      for($count = 0 ; $count < 11 ; $count++) {
        if($d = $criterion[$count]) {
          echo "order = $order[$count]   ";
          echo "criterion = $criterion[$count]   ";
          echo "dir = $dir[$d]   ";
          echo "joined = $joined[$count]\n";
          unset ($d);
        }
      }
      echo "</pre>\n";
    }
    rsort ($joined);
    reset ($joined);
    for($count = 0 ; $count < 11 ; $count++) {
      if(strlen($joined[$count]) == 3) {
        $cd = substr($joined[$count], 1, 2);
        $sorting = $sorting . $cd;
        if($debug) {
          echo "<pre>\n";
          echo "sorted = $joined[$count]   ";
          echo "cd = $cd   ";
          echo "sorting = $sorting\n";
          echo "</pre>\n";
        }
      }
    }
  }
  if(is_numeric($hide)) {
    $hide = "-m $hide";
  }
  if(is_numeric($top)) {
    $top = "-M $top";
  }
  if($old) {
    $old = "-l $old";
  }
  $parserstr = "$parsei$parsen$parsef$parsec$parsep$parsee$parsew$parsel$parses";
  if($parserstr) {
    $parser = "-P $parserstr";
  }
  $args = "-w$selectivity -O $sorting $hide $top $old $parser $logdir/$logfile";
  $report = `$fwlogwatch $args 2>&1`;
  if(!$debug) {
    $report = ereg_replace("<!DOCTYPE.*<body>", "", "$report");
    $report = ereg_replace("</body>.*</html>", "", "$report");
  }
  echo "\n$report\n";
  echo "  </td>\n";
  echo "</table>\n";
  echo "</form>\n";
}


function show() {
  global $logdir, $logfile, $HTTP_POST_VARS, $PHP_SELF;

  extract($HTTP_POST_VARS);
  $dir_logfile = $logdir . "/" . $logfile;
  if(!$amount) {
    $amount = 25;
  }
  if(!($end)) {
    $fd = gzopen($dir_logfile, r);
    for($i = 0; !gzeof($fd); $i++) {
      $lines[] = gzgets($fd, 4096);
    }
    $end = count($lines);
    $end = $end - 1;
    $total = $end;
  }
  if($cmd == "Prev") {
    $end = $end - $amount;
    $start = $end - $amount;
    $log = cut($dir_logfile, $start, $end, $total, $amount);
  } elseif($cmd == "Next") {
    $start = $end;
    $end = $end + $amount;
    $log = cut($dir_logfile, $start, $end, $total, $amount);
  } elseif($cmd == "Jump") {
    $end = $start + $amount;
    $log = cut($dir_logfile, $start, $end, $total, $amount);
  } else {
    $start = $end - $amount;
    $log = cut($dir_logfile, $start, $end, $total, $amount);
  }
  if($total) {
    if($start < 1) {
      $start = 1;
      $end = $start + $amount;
    }
    if($end > $total) {
      $end = $total;
      $start = $end - $amount;
    }
  }
  echo "<form method=\"post\" action=\"$PHP_SELF?view=show&amp;logfile=$logfile\">\n";
  echo "<table width=\"100%\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\">\n";
  echo "<tr>\n";
  if($start > 1) {
    echo "  <td>\n";
    echo "    <input type=\"submit\" name=\"cmd\" value=\"Prev\">\n";
    echo "  </td>\n";
  }
  echo "  <td>\n";
  echo "    Display lines:\n";
  echo "    <select name=\"amount\" onchange=\"this.form.submit()\">\n";
  echo "      <option selected=\"selected\" value=\"$amount\">$amount</option>\n";
  echo "      <option value=\"10\">10</option>\n";
  echo "      <option value=\"25\">25</option>\n";
  echo "      <option value=\"50\">50</option>\n";
  echo "      <option value=\"100\">100</option>\n";
  echo "      <option value=\"250\">250</option>\n";
  echo "      <option value=\"500\">500</option>\n";
  echo "    </select>\n";
  echo "  </td>\n";
  echo "  <td align=\"center\">\n";
  echo "    <b>Lines $start to $end of $total</b>\n";
  echo "  </td>\n";
  echo "  <td>\n";
  echo "    <a href=\"$PHP_SELF\">Back</a> / \n";
  echo "    <a href=\"$PHP_SELF?view=report&amp;logfile=$logfile\">Report</a>\n";
  echo "  </td>\n";
  echo "  <td>\n";
  echo "    Jump to line:\n";
  echo "    <input type=\"text\" size=\"8\" name=\"start\" value=\"$start\">\n";
  echo "    <input type=\"submit\" name=\"cmd\" value=\"Jump\">\n";
  echo "    <input type=\"hidden\" name=\"end\" value=\"$end\">\n";
  echo "    <input type=\"hidden\" name=\"total\" value=\"$total\">\n";
  echo "  </td>\n";
  if($total > $end) {
    echo "  <td>\n";
    echo "    <input type=\"submit\" name=\"cmd\" value=\"Next\">\n";
    echo "  </td>\n";
  }
  echo "</tr>\n";
  echo "</table>\n";
  echo "</form>\n";
  echo "<pre>\n";
  for($i = 0; $i < count($log); $i++) {
    echo $log[$i];
  }
  echo "</pre>\n";
}

?>
