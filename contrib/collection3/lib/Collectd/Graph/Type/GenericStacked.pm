package Collectd::Graph::Type::GenericStacked;

use strict;
use warnings;
use base ('Collectd::Graph::Type');

use Collectd::Graph::Common (qw($ColorCanvas $ColorFullBlue $ColorHalfBlue
  group_files_by_plugin_instance ident_to_filename sanitize_type_instance
  get_faded_color sort_idents_by_type_instance));

return (1);

sub getGraphsNum
{
  my $obj = shift;
  my $group = group_files_by_plugin_instance (@{$obj->{'files'}});

  return (scalar (keys %$group));
}

sub getRRDArgs
{
  my $obj = shift;
  my $index = shift;

  my $group = group_files_by_plugin_instance (@{$obj->{'files'}});
  my @group = sort (keys %$group);

  my $rrd_opts = $obj->{'rrd_opts'} || [];
  my $format = $obj->{'rrd_format'} || '%5.1lf';

  my $idents = $group->{$group[$index]};
  my $ds_name_len = 0;

  my $rrd_title = $obj->getTitle ($idents->[0]);

  my $colors = $obj->{'rrd_colors'} || {};
  my @ret = ('-t', $rrd_title, @$rrd_opts);

  if (defined $obj->{'rrd_vertical'})
  {
    push (@ret, '-v', $obj->{'rrd_vertical'});
  }

  if ($obj->{'custom_order'})
  {
    sort_idents_by_type_instance ($idents, $obj->{'custom_order'});
  }

  $obj->{'ds_names'} ||= {};
  my @names = map { $obj->{'ds_names'}{$_->{'type_instance'}} || $_->{'type_instance'} } (@$idents);

  for (my $i = 0; $i < @$idents; $i++)
  {
    my $ident = $idents->[$i];
    my $filename = ident_to_filename ($ident);

    if ($ds_name_len < length ($names[$i]))
    {
      $ds_name_len = length ($names[$i]);
    }
    
    # Escape colons _after_ the length has been checked.
    $names[$i] =~ s/:/\\:/g;

    push (@ret,
      "DEF:min${i}=${filename}:value:MIN",
      "DEF:avg${i}=${filename}:value:AVERAGE",
      "DEF:max${i}=${filename}:value:MAX");
  }

  for (my $i = @$idents - 1; $i >= 0; $i--)
  {
    if ($i == (@$idents - 1))
    {
      push (@ret,
	"CDEF:cdef${i}=avg${i}");
    }
    else
    {
      my $j = $i + 1;
      push (@ret,
	"CDEF:cdef${i}=cdef${j},avg${i},+");
    }
  }

  for (my $i = 0; $i < @$idents; $i++)
  {
    my $type_instance = $idents->[$i]{'type_instance'};
    my $color = '000000';
    if (exists $colors->{$type_instance})
    {
      $color = $colors->{$type_instance};
    }

    $color = get_faded_color ($color);

    push (@ret,
      "AREA:cdef${i}#${color}");
  }

  for (my $i = 0; $i < @$idents; $i++)
  {
    my $type_instance = $idents->[$i]{'type_instance'};
    my $ds_name = sprintf ("%-*s", $ds_name_len, $names[$i]);
    my $color = '000000';
    if (exists $colors->{$type_instance})
    {
      $color = $colors->{$type_instance};
    }
    push (@ret,
      "LINE1:cdef${i}#${color}:${ds_name}",
      "GPRINT:min${i}:MIN:${format} Min,",
      "GPRINT:avg${i}:AVERAGE:${format} Avg,",
      "GPRINT:max${i}:MAX:${format} Max,",
      "GPRINT:avg${i}:LAST:${format} Last\\l");
  }

  return (\@ret);
}

sub getGraphArgs
{
  my $obj = shift;
  my $index = shift;

  my $group = group_files_by_plugin_instance (@{$obj->{'files'}});
  my @group = sort (keys %$group);

  my $idents = $group->{$group[$index]};

  my @args = ();
  for (qw(hostname plugin plugin_instance type))
  {
    if (defined ($idents->[0]{$_}))
    {
      push (@args, $_ . '=' . $idents->[0]{$_});
    }
  }

  return (join (';', @args));
} # getGraphArgs


# vim: set shiftwidth=2 softtabstop=2 tabstop=8 :
