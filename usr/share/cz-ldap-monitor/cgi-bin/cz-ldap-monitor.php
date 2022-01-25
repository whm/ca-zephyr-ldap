<?php

// --------------------------------------------
// file: cz-ldap-monitor.php
// author: Bill MacAllister

if (strlen($_REQUEST['reload_interval']) == 0) {
    $_REQUEST['reload_interval'] = 60;
} elseif ($_REQUEST['reload_interval'] < 0) {
    $_REQUEST['reload_interval'] = 5;
}

require('/etc/cz-ldap-monitor.conf');

// ---------------------------------------------
// zulu date

function zulu_date ($in) {

  $out = $in;
  if (preg_match("/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})([\d\.]+)/",
                 $in,
                 $mat)) {
    $zYear   = $mat[1];
    $zMonth  = $mat[2];
    $zDay    = $mat[3];
    $zHour   = $mat[4];
    $zMinute = $mat[5];
    $zSecond = $mat[6];
    $out = $zYear.'-'.$zMonth.'-'.$zDay.' '.$zHour.':'.$zMinute.':'.$zSecond;
  }
  return $out;

}

// ---------------------------------------------
// zulu parts - break zulu time into pieces

function zulu_parts ($in) {

  $zYear = $zMonth = $zDay = $zHour = $zMinute = $zSecond = 0;

  if (preg_match("/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})([\d\.]+)/",
                 $in,
                 $mat)) {
    $zYear   = $mat[1];
    $zMonth  = $mat[2];
    $zDay    = $mat[3];
    $zHour   = $mat[4];
    $zMinute = $mat[5];
    $zSecond = $mat[6];
  }
  return array ($zYear, $zMonth, $zDay, $zHour, $zMinute, $zSecond);

}

// ---------------------------------------------
// difference in seconds between two zulu times

function zulu_diff ($start, $end) {

    // start
    list ($y, $m, $d, $hr, $min, $sec) = zulu_parts($start);
    $start_seconds = mktime($hr, $min, $sec, $m, $d, $y);

    // end
    list ($y, $m, $d, $hr, $min, $sec) = zulu_parts($end);
    $end_seconds = mktime($hr, $min, $sec, $m, $d, $y);

    return abs($end_seconds-$start_seconds);
}

// ---------------------------------------------
// connect and bind to directory server

function ldap_connect_anonbind ($ls) {

    global $warn, $ef;
    global $ldap_cache;

    if ($ldap_cache[$ls] < 1) {
        $dirServer = @ldap_connect($ls);
        if (ldap_errno ($dirServer) != 0) {
            $_SESSION['msg'] .= ldap_error ($dirServer);
            $_SESSION['msg'] .= "$warn ldap error connecting to $ls<br>";
            $_SESSION['msg'] .= ldap_error ($dirServer).$ef;
            $ldap_cache[$ls]++;
        }
        if (!ldap_set_option($dirServer, LDAP_OPT_TIMELIMIT, 1)) {
            $_SESSION['msg'] .= ldap_error ($dirServer);
            $_SESSION['msg'] .= "$warn problem setting search time limit<br>";
        }
        if (!ldap_set_option($dirServer, LDAP_OPT_NETWORK_TIMEOUT, 1)) {
            $_SESSION['msg'] .= ldap_error ($dirServer);
            $_SESSION['msg'] .= "$warn problem setting network timeout<br>";
        }
    }

    return $dirServer;
}

// ---------------------------------------------
// format number of seconds in days, minutes, seconds

function duration_format ($sec) {

    $dur = '';

    $days = floor ($sec/86400);
    if ($days > 0) {
        $sec -= $days*86400;
        $dur = $days . ' Days ';
    }

    $hrs = floor($sec/3600);
    if ($hrs > 0) {
        $sec -= $hrs*3600;
    }

    $min = floor($sec/60);
    if ($min > 0) {
        $sec -= $min*60;
    }

    $dur .= sprintf ('%02.2d:%02.2d:%02.2d',$hrs,$min,$sec);

    return $dur;

}

// ---------------------------------------------
// Get contextCSN

function info_contextcsn ($id, $ls) {

  global $serverGroups;
  global $dirServer;
  global $ldapinfo;
  global $dnList;

  $filter = 'objectclass=*';
  $return_attr = array('contextcsn');
  $br = '';

  $ldapinfo[$id]['contextcsn']    = '';
  $ldapinfo[$id]['contextcsnRaw'] = '';

  foreach ($dnList as $base_dn) {
    $ldapinfo[$id]['contextcsn']    .= "$br  $base_dn:\n";
    $ldapinfo[$id]['contextcsnRaw'] .= $ldapinfo[$id]['contextcsn'];
    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
      $csn_br = "<br/>\n    ";
      for ($i=0; $i<$ret_cnt; $i++) {
          $csn_cnt = $info[$i]['contextcsn']['count'];
          for ($j=0; $j<$csn_cnt; $j++) {
              $csn = $info[$i]["contextcsn"][$j];
              $csn_bits = explode('#', $csn);
              $csn_zulu = $csn_bits[0];
              $csn_rid  = $csn_bits[2];
              $csn_display = $csn_br . $csn_rid . ': ' . zulu_date($csn_zulu);
              $csn_raw     = $csn_br . $csn;
              $ldapinfo[$id]['contextcsn']    .= $csn_display;
              $ldapinfo[$id]['contextcsnRaw'] .= $csn_raw;
          }
      }
    } else {
      $ldapinfo[$id]['contextcsn']
          .= '<font color="red">Connect Failed</font>';
      $ldapinfo[$id]['contextcsnRaw']
          .= '<font color="red">Connect Failed</font>';
    }
    $br = "<br/>\n";
  }
  return;
}

// ---------------------------------------------
// Get naming contexts information

function info_namingcontexts ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Databases,cn=monitor';
    $filter = 'namingcontexts=*';
    $return_attr = array('namingcontexts');
    $br = '';

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        $ldapinfo[$ls]['dbdn'] = $info[0]["dn"];
        for ($i=0; $i<$ret_cnt; $i++) {
            $nc_cnt = $info[$i]['namingcontexts']['count'];
            for ($j=0; $j<$nc_cnt; $j++) {
                $nc = $info[$i]["namingcontexts"][$j];
                if (empty($nc)) {
                  $nc = "cn=''";
                }
                $ldapinfo[$id]['namingcontexts']
                    .= $br.$info[$i]["namingcontexts"][$j];
                $br = "<br>\n";
            }
        }
    } else {
        $ldapinfo[$id]['namingcontexts']
             = '<font color="red">Connect Failed</font><br>';
    }
}

// ---------------------------------------------
// Get sasl mechanisms

function info_sasl ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = '';
    $filter = 'objectclass=*';
    $return_attr = array('+');
    $br = '';

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $sasl_cnt = $info[$i]['supportedsaslmechanisms']['count'];
            for ($j=0; $j<$sasl_cnt; $j++) {

                $sasl = $info[$i]["supportedsaslmechanisms"][$j];
                $ldapinfo[$id]['sasl'] .= $br.$sasl;
                $br = "<br>\n";
            }
        }
    }
}

// ---------------------------------------------
// Get current time

function info_currenttime ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Current,cn=Time,cn=Monitor';
    $filter = '(objectclass=monitoredObject)';
    $return_attr = array('monitortimestamp');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $ldapinfo[$id]["currentTime"] .= $info[0]["monitortimestamp"][0];
        }
    }
}

// ---------------------------------------------
// Get start time

function info_starttime ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Start,cn=Time,cn=Monitor';
    $filter = '(objectclass=monitoredObject)';
    $return_attr = array('monitortimestamp');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $ldapinfo[$id]["startTime"] .= $info[0]["monitortimestamp"][0];
        }
    }

}

// ---------------------------------------------
// Get current connections

function info_currentconns ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Current,cn=Connections,cn=Monitor';
    $filter = '(objectclass=monitorCounterObject)';
    $return_attr = array('monitorcounter');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $nc_cnt = $info[$i]['monitorcounter']['count'];
            for ($j=0; $j<$nc_cnt; $j++) {
                $ldapinfo[$id]["currentConns"]
                    += $info[$i]["monitorcounter"][$j];
            }
        }
    }
}

// ---------------------------------------------
// Get total connections

function info_totalconns ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Total,cn=Connections,cn=Monitor';
    $filter = '(objectclass=monitorCounterObject)';
    $return_attr = array('monitorcounter');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $nc_cnt = $info[$i]['monitorcounter']['count'];
            for ($j=0; $j<$nc_cnt; $j++) {
                $ldapinfo[$id]["totalConns"]
                    += $info[$i]["monitorcounter"][$j];
            }
        }
    }
}

// ---------------------------------------------
// Get total connections

function info_operations ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Operations,cn=Monitor';
    $filter = '(objectclass=monitorOperation)';
    $return_attr = array('monitoropinitiated','monitoropcompleted');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_search($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $thisDN       = $info[$i]['dn'];
            $thisStarted  = $info[$i]['monitoropinitiated'][0];
            $thisFinished = $info[$i]['monitoropcompleted'][0];
            $dnParts = ldap_explode_dn($thisDN,0);
            $thisOp = str_replace ('cn=','',strtolower($dnParts[0]));
            $ldapinfo[$id][$thisOp]['started'] = $thisStarted;
            $ldapinfo[$id][$thisOp]['finished'] = $thisFinished;
        }
    }
}

// ---------------------------------------------
// Get server version

function info_version ($id, $ls) {

    global $serverGroups;
    global $dirServer;
    global $ldapinfo;

    $base_dn = 'cn=Monitor';
    $filter = '(objectclass=monitorServer)';
    $return_attr = array('monitoredinfo');

    $dirServer = ldap_connect_anonbind($ls);
    $sr = @ldap_read($dirServer, $base_dn, $filter, $return_attr);
    $info = @ldap_get_entries($dirServer, $sr);
    $ret_cnt = $info["count"];
    if ($ret_cnt) {
        for ($i=0; $i<$ret_cnt; $i++) {
            $nc_cnt = $info[$i]['monitoredinfo']['count'];
            for ($j=0; $j<$nc_cnt; $j++) {
                $ldapinfo[$id]["version"] = $info[$i]["monitoredinfo"][$j];
            }
        }
    }
}

// ---------------------------------------------
// Get monitor information

function get_info ($type) {

    global $serverGroups;

    // Count the number of groups
    $group_cnt = 0;
    foreach ($serverGroups as $group => $lserver) {
        $group_cnt++;
    }

    // Get information for each server in the groups of concern.
    // It there is only one group perform the lookups unconditionally.
    foreach ($serverGroups as $group => $lserver) {
        if (!$_REQUEST['chk_'.$group] && $group_cnt>1) {
            continue;
        }
        foreach ($lserver as $id => $ls) {
            $subName = 'info_'.$type;
            $subName($id, $ls);
        }
    }
}

// Figure out what we are monitoring
$radio_list = '';
$refresh_list = '';

$chk_cnt = 0;
$group_cnt = 0;
foreach ($serverGroups as $group => $lserver) {
    $group_cnt++;
    $name  = 'chk_'.$group;
    $rname = 'rchk_'.$group;
    if (strlen($_REQUEST['btn_refresh'])>0) {
        $val = $_REQUEST[$name];
    } else {
        $val = $_REQUEST[$rname];
        $_REQUEST[$name] = $val;
    }
    $chk = '';
    if (strlen($val) > 0) {
        $chk = ' CHECKED ';
        $chk_cnt++;
        $refresh_list .= '&' . $rname .'=Y';
        $sep = '&';
    }
    $radio_list .= "$group <input type=\"checkbox\" "
        . "name=\"$name\" value=\"Y\" $chk> &nbsp;&nbsp;&nbsp;\n";
}

?>
<html>
<head>
<title>LDAP Server Counters</title>
<script language="JavaScript">

function re_it() {
    location.replace('cz-ldap-monitor.php?reload_interval=<?php echo $_REQUEST['reload_interval'].$refresh_list;?>');
}

// refresh the page automatically
setTimeout ("re_it();", <?php echo $_REQUEST['reload_interval']*1000;?>);

</script>
</head>

<body bgcolor="#eeeeff">

<div align="center">
<h1>LDAP Server Counters</h1>
<form name="find_form"
      method="post"
      action="<?php print $PHP_SELF; ?>">
<table border="0" cellpadding="5">
 <tr>
  <td align="center">
    <input type="submit" name="btn_refresh" value="Refresh">
  </td>
  <td>
  <table border="0">

   <?php if ($group_cnt>1) { ?>
   <tr>
    <td align="right">Server Group:</td>
    <td><?php echo $radio_list;?></td>
   </tr>
   <?php } ?>

   <tr>
    <td align="right">Reload Interval:</td>
    <td>
      <input type="text" size="6"
             value="<?php echo $_REQUEST['reload_interval'];?>"
             name="reload_interval">
    </td>
   </tr>

  </table>
  </td>
 </tr>
</table>
</table>
</form>


<?php

get_info('namingcontexts');
get_info('sasl');
get_info('currenttime');
get_info('starttime');
get_info('currentconns');
get_info('totalconns');
get_info('operations');
get_info('version');
get_info('contextcsn');

?>

<br>

<table border="1" cellpadding="2">

<tr>
  <th rowspan="2">Server</th>
  <th rowspan="2">Version</th>
  <th rowspan="2">SASL</th>
  <th rowspan="2">Data Bases</th>
  <th rowspan="2">Up Time</th>
  <th rowspan="2">ContextCSN</th>
  <th colspan="2">Connections</th>
  <th colspan="5">Operations</th>
</tr>
<tr>
  <th>Current</th>
  <th>Total</th>
  <th>Bind</th>
  <th>Search</th>
  <th>Add</th>
  <th>Delete</th>
  <th>Modify</th>
</tr>

<?php

foreach ($serverGroups as $group => $lserver) {
    foreach ($lserver as $id => $ls) {

        // skip display if not selected
        if (!$_REQUEST['chk_'.$group] && $group_cnt>1) {
            continue;
        }
        if (strlen($ldapinfo[$id]['currentTime']) > 0) {
            $upTime = duration_format(zulu_diff($ldapinfo[$id]['currentTime'],
                                                $ldapinfo[$id]['startTime']));
        } else {
            $upTime = 'na';
        }
        $sasl    = $ldapinfo[$id]['sasl'];
        $version = str_replace ('(','<BR>(',$ldapinfo[$id]['version']);
        if ($debug) {
            $csn = $ldapinfo[$id]['contextcsnRaw'];
        } else {
            $csn = $ldapinfo[$id]['contextcsn'];
        }
        echo "<tr>\n";
        echo " <td align=\"center\" valign=\"top\">".$id."</td>\n";
        echo " <td valign=\"top\">$version</td>\n";
        echo " <td valign=\"top\">$sasl</td>\n";
        echo " <td valign=\"top\">".$ldapinfo[$id]['namingcontexts']."</td>\n";
        echo " <td valign=\"top\" align=\"center\">$upTime</td>\n";

        echo " <td valign=\"top\">".$csn;
        echo "</td>\n";

        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['currentConns'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['totalConns'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['bind']['finished'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['search']['finished'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['add']['finished'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['delete']['finished'])."</td>\n";
        echo " <td valign=\"top\" align=\"right\">"
            .number_format($ldapinfo[$id]['modify']['finished'])."</td>\n";
        echo "</tr>\n";

    }
}
?>

</table>
</div>

<?php
if (strlen($_SESSION['msg'])>0) {
    echo $_SESSION['msg'];
    $_SESSION['msg'] = '';
}
?>
</body>
</html>
<?php

/*
############################################################################
# Documentation
############################################################################

$pod = "
=head1 NAME

cz-ldap-monitor.php

=head1 SYNOPSIS

cz-ldap-monitor.php

=head1 DESCRIPTION

This script is intended to be run as a CGI script under the control
of a web server.  It queries OpenLDAP servers and displays statistics
from cn=monitor, displays the replication status, and displays the
build version of the slapd process.

=head1 CONFIGURATION

The script reads the configuration file /etc/cz-ldap-monitor.conf.  The
configuration file must be valid php and defines server groups,
servers, and base DNs to be reported.  The configuration file must define
the following two variables.

=over 4

=item $serverGroups

$serverGroups is a hash that defines server groups and group
members.

=item $dnList

$dnList is an array that defines list the root DNs of the replicated
backends.

=back

=head2 Configuration Example

    <?php
    // file: /etc/cz-ldap-monitor.conf

    $serverGroups['cz']['master'] = 'ldap-master.ca-zephyr.internal';
    $serverGroups['cz']['slave-1']  = 'slave-1.ca-zephyr.internal';
    $serverGroups['cz']['slave-2']  = 'slave-2.ca-zephyr.internal';
    $dnList = array(
         'dc=macallister,dc=grass-valley,dc=ca,dc=us',
         'dc=ca-zephyr,dc=org');
    ?>

=head1 AUTHOR

Bill MacAllister <bill@ca-zephyr.org>

=head1 COPYRIGHT

Copyright 2019 <bill@ca-zephyr.org> Bill MacAllister
All rights reserved.

=cut
*/
?>