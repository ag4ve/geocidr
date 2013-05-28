#!/usr/bin/env perl 
#===============================================================================
#
#         FILE:  geocidr.pl
#
#        USAGE:  ./geocidr.pl  
#
#  DESCRIPTION:  
#
#      OPTIONS:  ---
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Shawn Wilson <swilson@korelogic.com>
#      COMPANY:  Korelogic
#      VERSION:  1.0
#      CREATED:  05/24/13 04:21:17
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;

$SIG{INT} = 'current_ip';

use Getopt::Long;
use Pod::Usage;

use Net::IP;
use Net::CIDR qw(cidrlookup);
use Net::DNS::Resolver;
use Net::DNS::Packet;

my $opts;
GetOptions('ip=s@'      => \$opts->{ip},
          'mask|d=s'    => \$opts->{mask},
          'indent|i'    => \$opts->{indent},
        ) or pod2usage( -verbose => 0, -output => \*STDERR, 
          -msg => "$0 no parameter found.\n" .
                  "Use -help for more options.\n"
        );
if ($opts->{man})
{
  pod2usage( -verbose => 2 ); 
}
elsif ($opts->{help} or scalar(@{$opts->{ip}}) < 1)
{
  pod2usage( -verbose => 0, -output => \*STDERR,
              -msg => "$0 [options]\n");
}

$opts->{mask} //= 32;

# Currently processed ip should be global for reporting
my $ip = Net::IP->new('0.0.0.0/0') or die (Net::IP::Error());
my $one = Net::IP->new('0.0.0.1');

for my $i (@{$opts->{ip}})
{
  per_ip($i);
}

sub per_ip
{
  my ($ip_str) = @_;

  print "IP: $ip_str\n";
  $ip_str .= "/32" unless ($ip_str =~ m%/[0-9]{1,2}%);
  $ip->set($ip_str) or die (Net::IP::Error());

  while (cidrlookup($ip->ip, $ip_str))
  {
    my @octets = split_ip($ip->ip);
    my ($asn, $cidr, $country, $nic, $date) = asn_map(@octets);
    my $mask = $opts->{mask};
    my $addr = "0.0.0.0";
  
    if ($asn and $cidr and $country and $nic and $date)
    {
      my $curmask;
      ($addr, $curmask) = split("/", $cidr);
      $mask = (($curmask > $mask) ? $mask : $curmask);
      print " * " . net_space($curmask) . "[$cidr] [$country]\n";
    }
    else
    {
      print " * " . net_space($mask) . "[" . $ip->ip . "/$mask] [NONE]\n";
      $addr = $ip->ip;
    }

    $ip->set($addr . "/" . $mask) or die (Net::IP::Error());
    $ip->set($ip->last_ip) or die (NET::IP::Error());
    $ip = $ip->binadd($one);
  }
}

sub asn_map
{
  my (@octets) = @_;

  my $lookup = join('.', reverse(@octets), 'origin.asn.cymru.com') . '.';
  my $resolver = Net::DNS::Resolver->new;
  my $packet = Net::DNS::Packet->new($lookup, 'TXT');
  my $response = $resolver->send($packet);

  my $rec = join ', ', map { $_->rdatastr } grep { $_->type eq 'TXT' } $response->answer;

  return split(/ \| /, $rec);
}

sub split_ip
{
  my ($ip_str) = @_;
  my @octets = split(/\./, $ip_str);
  return @octets;
}

sub current_ip
{
  print STDERR "IP [" . $ip->ip . "]\n";
  exit;
}

sub net_space
{
  my ($mask) = @_;

  return ($opts->{indent} ? " " x $mask : "");
}

