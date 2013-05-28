
# Installer for probe_summ

use strict;

use ExtUtils::MakeMaker 6.630;

WriteMakefile(
  NAME              => 'geocidr',
  AUTHOR            => 'Shawn Wilson <swilson@korelogic.com>',
  ABSTRACT          => 'Display AS information for a list of CIDR networks',
  VERSION           => '1.0',
  INST_SCRIPT       => '/usr/local/bin',
  EXE_FILES         => [ qw(geocidr) ],
  MIN_PERL_VERSION  => 5.010,
  SIGN              => 1,
  dist              => {
        COMPRESS => 'gzip',
        SUFFIX   => 'gz'
  },
  PREREQ_PM         => {
        'Net::DNS::Resolver'    => 1088,
        'Net::IP'               => 1.260,
        'Net::CIDR'             => 0.170,
  },
);

