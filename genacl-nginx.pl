#!/usr/bin/env perl
use 5.010;
use strict;
use warnings;
use Socket;
use File::Slurp;

sub resolve_addr {
    my $hostname = shift;
    my ($error, @responses) = Socket::getaddrinfo(
        $hostname,
        "", 
        { socktype => Socket::SOCK_RAW }
    );

    # FIXME: 엉망진창 오류 처리
    map { 
        my (undef, $ipaddr) = Socket::getnameinfo(
            $_->{addr},
            Socket::NI_NUMERICHOST,
            Socket::NIx_NOSERV
        );
        $_ = $ipaddr;
    } @responses; 
}

my @acl_list = read_file('acl.txt');
my $buffer = '';

for my $rule (@acl_list) {
    chomp $rule;
    my ($type, $addr) = $rule =~ m/^(\w+):(.+)$/ or next;
    $buffer .= "# $rule\n";

    if ($type eq 'domain') {
        my @addresses = resolve_addr($addr); 
        $buffer .= sprintf("allow %s;\n", $_) for @addresses;
    } elsif ($type eq 'ip') {
        $buffer .= sprintf("allow %s;\n", $addr);
    }
}

write_file('nginx-relay-acl.conf', $buffer);

