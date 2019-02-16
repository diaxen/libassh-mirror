#
# this script can be used to generate ssh packet encoders and decoders
# from rfc like text description.
#
# %name flags description
#   field_type field name description
#   ...
#
# type: buffer  string
# type: charstr string
# type: uint32  uint32
# type: boolean boolean
#
# flag: C sent by client
# flag: S sent by server
# flag: R channel request
# flag: G global request
# flag: K request reply
# flag: O channel open
# flag: A want reply must be true
# flag: E want reply must be false

use strict;

our $prefix = "assh_inter";

my $packet;

open(HFILE, ">parse.h") or die;

print HFILE "
#include \"assh.h\"
#include \"assh_buffer.h\"
#include \"assh_packet.h\"
#include \"assh_connection.h\"
";

open(CFILE, ">parse.c") or die;

print CFILE "
#include \"parse.h\"
";


my %ops = (
    buffer => {
	constsize => 0,
	struct_type => "struct assh_cbuffer_s",
	init_type => "const struct assh_cbuffer_s *",
	init => sub {
	    my $f = shift;
	    return "  i->$f->{name} = *$f->{name};";
	},
	size => sub {
	    my $f = shift;
	    return "4 + i->$f->{name}.size";
	},
	encode => sub {
	    my $f = shift;
	    return "  size_t $f->{name}_size = i->$f->{name}.size;\n"
		."  assh_store_u32(d, $f->{name}_size);\n"
		."  memcpy(d + 4, i->$f->{name}.data, $f->{name}_size);\n"
		."  d += 4 + $f->{name}_size;";
	},
	decode => sub {
	    my $f = shift;
	    return "  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));\n"
		."  i->$f->{name}.data = d + 4;\n"
		."  i->$f->{name}.size = n - d - 4;\n"
		."  d = n;";
	}
    },
    charstr => {
	constsize => 0,
	struct_type => "struct assh_cbuffer_s",
	init_type => "const char *",
	init => sub {
	    my $f = shift;
	    return "  i->$f->{name}.str = $f->{name};\n"
		."  i->$f->{name}.len = $f->{name} ? strlen($f->{name}) : 0;";
	},
	size => sub {
	    my $f = shift;
	    return "4 + i->$f->{name}.size";
	},
	encode => sub {
	    my $f = shift;
	    return "  size_t $f->{name}_size = i->$f->{name}.size;\n"
		."  assh_store_u32(d, $f->{name}_size);\n"
		."  memcpy(d + 4, i->$f->{name}.data, $f->{name}_size);\n"
		."  d += 4 + $f->{name}_size;";
	},
	decode => sub {
	    my $f = shift;
	    return "  ASSH_RET_ON_ERR(assh_check_string(data, size, d, &n));\n"
		."  i->$f->{name}.data = d + 4;\n"
		."  i->$f->{name}.size = n - d - 4;\n"
		."  d = n;";
	}
    },
    uint32 => {
	constsize => 4,
	struct_type => "uint32_t",
	init_type => "uint32_t",
	init => sub {
	    my $f = shift;
	    return "  i->$f->{name} = $f->{name};";
	},
	size => sub {
	    my $f = shift;
	    return "4";
	},
	encode => sub {
	    my $f = shift;
	    return "  assh_store_u32(d, i->$f->{name});\n"
		."  d += 4;";
	},
	decode => sub {
	    my $f = shift;
	    return "  i->$f->{name} = assh_load_u32(d);\n"
		."  d += 4;";
	}
    },
    boolean => {
	constsize => 1,
	struct_type => "assh_bool_t",
	init_type => "assh_bool_t",
	init => sub {
	    my $f = shift;
	    return "  i->$f->{name} = $f->{name};";
	},
	size => sub {
	    my $f = shift;
	    return "1";
	},
	encode => sub {
	    my $f = shift;
	    return "  *d++ = i->$f->{name};";
	},
	decode => sub {
	    my $f = shift;
	    return "  i->$f->{name} = *d++;";
	}
    }
);

sub packet_start
{
    my ( $name, $flags, $desc ) = @_;

    my $id = $name;
    $id =~ s/\W/_/g;

    $packet = {
	name => $name,
	flags => $flags,
	desc => $desc,
	id => $id,
	fields => [],
    };
}

sub packet_field
{
    my ( $type, $name, $doc ) = @_;

    my $f = $packet->{fields};

    push @$f, {
	type => $type,
	name => $name,
	doc => $doc,
    };
}

sub init_proto
{
    my ( $f ) = @_;

    my $pid = "${prefix}_init_$packet->{id}";
    my $indent = ' 'x length $pid;

    my $init_proto = "
void
$pid(struct ${prefix}_$packet->{id}_s *i";

    foreach my $e (@$f) {
	my $t = $ops{$e->{type}};
	die $e->{type} if !$t;
	$init_proto .= sprintf ",\n%s %s %s", $indent, $t->{init_type}, $e->{name};
    }

    return $init_proto . ")";
}

sub packet_end
{
    return unless defined $packet;

    my $pid = "${prefix}_$packet->{id}";
    my $indent = ' 'x (1 + length $pid);

    my ( $out_ifdef, $in_ifdef );

    if ( $packet->{flags} =~ /C/ ) {
	$out_ifdef = "\n#ifdef CONFIG_ASSH_CLIENT\n";
	$in_ifdef = "\n#ifdef CONFIG_ASSH_SERVER\n";
    } elsif ( $packet->{flags} =~ /C/ ) {
	$in_ifdef = "\n#ifdef CONFIG_ASSH_CLIENT\n";
	$out_ifdef = "\n#ifdef CONFIG_ASSH_SERVER\n";
    }

    ######################### struct

    my $f = $packet->{fields};

    if (@$f) {
	print HFILE "\n/** \@This specifies the $packet->{desc} object. */
struct ${prefix}_$packet->{id}_s
{
";

	foreach my $e (@$f) {
	    my $t = $ops{$e->{type}};
	    die $e->{type} if !$t;
	    printf HFILE "  %-32s %s;\n", $t->{struct_type}, $e->{name};
	}

	print HFILE "};
";
    }

    ######################### proto

    print HFILE $out_ifdef if defined $out_ifdef;

    if (@$f) {

	print HFILE "
/** \@This initializes a $packet->{desc} object.
    Any buffer passed to the function is not copied and
    must remain valid. */";

	print HFILE init_proto($f).";

/** \@This returns the size of the buffer required to encode a
    $packet->{desc} object. */";

	print HFILE "
size_t
${prefix}_size_$packet->{id}(const struct ${prefix}_$packet->{id}_s *i);
";

	print HFILE "
/** \@This encodes the $packet->{desc} in a buffer suitable for
    calling the \@ref assh_request function. This function fails when
    the provided buffer is not large enough. */";

	print HFILE "
ASSH_WARN_UNUSED_RESULT assh_error_t
${prefix}_encode_$packet->{id}(uint8_t *data, size_t size,
${indent}       const struct ${prefix}_$packet->{id}_s *i);
";
    }

    my $send_proto;

    if ( $packet->{flags} =~ /[RG]/ ) {
	print HFILE "
/** \@This encodes and sends a $packet->{desc}";
	if (@$f) {
	    print  HFILE "
    \@csee ${prefix}_encode_$packet->{id}";
	}
	print  HFILE "
    \@see assh_request */";

	$send_proto .= "assh_error_t
${prefix}_send_$packet->{id}(struct assh_session_s *s";

	if ( $packet->{flags} !~ /[G]/ ) {
	    $send_proto .= ",
${indent}     struct assh_channel_s *ch";
	}

	if ( $packet->{flags} !~ /[E]/ ) {
	    $send_proto .= ",
${indent}     struct assh_request_s **rq";
	}

	if (@$f) {
	    $send_proto .= ",
${indent}     const struct ${prefix}_$packet->{id}_s *i";

	}
	$send_proto .= ")";

	print HFILE "
ASSH_WARN_UNUSED_RESULT ".$send_proto.";
";

    } elsif ( $packet->{flags} =~ /[O]/ ) {
	print HFILE "
/** \@This requests a $packet->{desc} open.";
	if (@$f) {
	    print  HFILE "
    \@csee ${prefix}_encode_$packet->{id}";
	}
	print  HFILE "
    \@see assh_channel_open */";

	$send_proto .= "assh_error_t
${prefix}_open_$packet->{id}(struct assh_session_s *s,
${indent}     struct assh_channel_s **ch";

	if (@$f) {
	    $send_proto .= ",
${indent}     const struct ${prefix}_$packet->{id}_s *i";

	}
	$send_proto .= ")";

	print HFILE "
ASSH_WARN_UNUSED_RESULT ".$send_proto.";
";
    }

    print HFILE "#endif\n" if defined $out_ifdef;

    if (@$f) {
	print HFILE $in_ifdef if defined $in_ifdef;

	print HFILE "
/** \@This function decodes the $packet->{desc} object from the passed
    buffer. The \@tt data buffer must remain valid because string
    buffers are not copied. This function fails when the buffer contains
    invalid data. */";

	print HFILE "
ASSH_WARN_UNUSED_RESULT assh_error_t
${prefix}_decode_$packet->{id}(struct ${prefix}_$packet->{id}_s *i,
${indent}       const uint8_t *data, size_t size);
";
	print HFILE "#endif\n" if defined $in_ifdef;
    }

    ######################### functions

    print CFILE $out_ifdef if defined $out_ifdef;

    if (@$f) {

	print CFILE init_proto($f)."
{
";

	foreach my $e (@$f) {
	    my $t = $ops{$e->{type}};
	    die $e->{type} if !$t;
	    print CFILE $t->{init}->($e)."\n";
	}

	print CFILE "}

size_t
${prefix}_size_$packet->{id}(const struct ${prefix}_$packet->{id}_s *i)
{
";

	my $h = "  return ";
	foreach my $e (@$f) {
	    my $t = $ops{$e->{type}};
	    die $e->{type} if !$t;
	    printf CFILE "$h%-32s/* %s */\n", $t->{size}->($e), $e->{name};
	    $h = "       + ";
	}

    print CFILE"       ;
}

assh_error_t
${prefix}_encode_$packet->{id}(uint8_t *data, size_t size,
				const struct ${prefix}_$packet->{id}_s *i)
";

    print CFILE "
{
  assh_error_t err;

  ASSH_RET_IF_TRUE(${prefix}_size_$packet->{id}(i) > size,
	       ASSH_ERR_OUTPUT_OVERFLOW);

  uint8_t *d = data;
";

    foreach my $e (@$f) {
	my $t = $ops{$e->{type}};
	die $e->{type} if !$t;
	print CFILE "\n".$t->{encode}->($e)."\n";
    }

    print CFILE"
  return ASSH_OK;
}
";
    }

    if ( $packet->{flags} =~ /[RGO]/ ) {

    print CFILE $send_proto."
";

    print CFILE "
{
  assh_error_t err;
";

    if (@$f) {
    print CFILE "
  size_t sz = ${prefix}_size_$packet->{id}(i);
  uint8_t buf[sz];

  ASSH_ASSERT(${prefix}_encode_$packet->{id}(buf, sz, i));
";
    }

    if ( $packet->{flags} =~ /[R]/ ) {
	print CFILE "  ASSH_RET_ON_ERR(assh_request(s, ch, ";
    } elsif ( $packet->{flags} =~ /[G]/ ) {
	print CFILE "  ASSH_RET_ON_ERR(assh_request(s, NULL, ";
    } else {
	print CFILE "  ASSH_RET_ON_ERR(assh_channel_open(s, ";
    }

    print CFILE "\"$packet->{name}\", ".
	(length $packet->{id}). ", ";

    if (@$f) {
	print CFILE "buf, sz, ";
    } else {
	print CFILE "NULL, 0, ";
    }

    if ( $packet->{flags} =~ /[O]/ ) {
	print CFILE "ch";
    } elsif ( $packet->{flags} !~ /[E]/ ) {
	print CFILE "rq";
    } else {
	print CFILE "NULL";
    }

    print CFILE "));

  return ASSH_OK;
}
";
    }

    print CFILE "#endif\n" if defined $out_ifdef;

    if (@$f) {
	print CFILE $in_ifdef if defined $in_ifdef;
	print CFILE "
assh_error_t
${prefix}_decode_$packet->{id}(struct ${prefix}_$packet->{id}_s *i,
${indent}       const uint8_t *data, size_t size)
";

	print CFILE "
{
  assh_error_t err;
  const uint8_t *n, *d = data;
";

	my $sz;
	my @l;
	my $flush = sub {
	    return unless $sz;
	    print CFILE "
  ASSH_RET_ON_ERR(assh_check_array(data, size, d, $sz, &n));
";
	    foreach my $e (@l) {
		my $t = $ops{$e->{type}};
		die $e->{type} if !$t;
		print CFILE "\n".$t->{decode}->($e)."\n";
	    }
	    $sz = 0;
	    @l = ();
	};

	foreach my $e (@$f) {
	    my $t = $ops{$e->{type}};
	    my $c = $t->{constsize};

	    if (!$c) {
		$flush->();
		print CFILE "\n".$t->{decode}->($e)."\n";
	    } else {
		push @l, $e;
		$sz += $c;
	    }
	}
	$flush->();

	print CFILE "
  return ASSH_OK;
}
";
	print CFILE "#endif\n" if defined $in_ifdef;
    }

}

my $n = 1;
foreach my $l (<STDIN>) {
    if ( $l =~ /^\s*#/) {
    } elsif ( $l =~ /^\s*$/) {
    } elsif ( $l =~ /^%(\S+)\s+([CSRGKOAE]+)\s+([^\n]*)/) {
	packet_end();
	packet_start($1, $2, $3);
    } elsif ( $l =~ /^\s*(\w+)\s+(\w+)\s*([^\n]*)/ ) {
	packet_field($1, $2, $3);
    } else {
	die "$n:error:$l\n";
    }
    $n++;
}

packet_end();

