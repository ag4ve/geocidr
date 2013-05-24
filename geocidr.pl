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

use Net::CIDR qw(cidr2range cidrlookup);
use Net::DNS::Resolver;
use Net::DNS::Packet;

my ($start, $end) = ip_range($ARGV[0]);

my $last = next_ip($end);
my $ip = $start;

while (cidrlookup($ip, $ARGV[0]))
{
  my @octets = split_ip($ip);
  my ($asn, $cidr, $country, $nic, $date) = asn_map(@octets);

  if ($asn and $cidr and $country and $nic and $date)
  {
    print "[$cidr] [$country]\n";

    my ($sip, $eip) = ip_range($cidr);

    $ip = next_ip($eip);
  }
  else
  {
    $ip = next_ip($ip);
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

sub ip_range
{
  my ($ip_str) = @_;

  my $range = join("", cidr2range($ip_str));
  my ($sip, $eip) = split("-", $range);

  return $sip, $eip;
}

sub split_ip
{
  my ($ip_str) = @_;
  my @octets = split(/\./, $ip_str);
  return @octets;
}

sub next_ip
{
  my ($ip_str) = @_;

  my @blocks = split_ip($ip_str);

  my $shifted = 0;
  foreach my $i (reverse(0 .. $#blocks))
  {
    if ($blocks[$i] == 255)
    {
      last if ($i == 0);
      $blocks[$i] = 0;
      $blocks[$i -1]++;
      $shifted = 1;
    }
  }

  $blocks[3]++ unless ($shifted);

  return join(".", @blocks);
}

sub current_ip
{
  print STDERR "IP [$ip]\n";
  exit;
}


