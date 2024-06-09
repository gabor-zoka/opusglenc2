#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> /* PRIu64 */
#include <math.h>
#include <regex.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <locale.h>
#include <unistd.h>
#include <libgen.h>
#include <arpa/inet.h>

#include <FLAC/metadata.h>
#include <FLAC/stream_decoder.h>
#include <opusenc.h>

#define IMIN(a,b) ((a) < (b) ? (a) : (b))   /**< Minimum int value.   */
#define IMAX(a,b) ((a) > (b) ? (a) : (b))   /**< Maximum int value.   */



typedef struct {
  size_t           idx;
  OggOpusEnc*      enc;
  unsigned         initialized;

  // Cmd params:

  opus_int32       bitrate;
  int              individual;

  // Aggregated attribs:

  unsigned         max_blocksize;
  unsigned         max_channels;
  unsigned         min_bits_per_sample;
  char**           inp_paths;
  char**           out_paths;
  size_t           num_paths;
  float*           enc_buffer;

  // STREAMINFO attribs:

  double           scale;
  unsigned         channels;
  unsigned         sample_rate;
  opus_int32       serialno;

  // Previous STREAMINFO attribs:

  double           prev_scale;
  unsigned         prev_channels;
  unsigned         prev_sample_rate;

  // Metadata:

  OggOpusComments* opus_comments;
  char**           comments;
  size_t           num_comments;

} Data;



const char version[]    = "2.3";
const int  max_channels =  2;

int        exit_warning =  1;
double     rg_offset;
char*      prg;



void
warning(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);

  if (exit_warning)
    exit(EXIT_FAILURE);
}



void
fatal(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);

  exit(EXIT_FAILURE);
}



void*
my_malloc(size_t size) {
  void* ret = malloc(size);

  if (size != 0 && ret == NULL)
    fatal("ERROR: Out of memory\n");

  return ret;
}



char*
my_sprintf(const char* format, ...) {
  va_list  ap1, ap2;
  va_start(ap1, format);
  va_copy (ap2, ap1);

  const int len = vsnprintf(NULL, 0, format, ap1) + 1;
  va_end(ap1);

  char* buf = my_malloc(len);

  vsnprintf(buf, len, format, ap2);
  va_end(ap2);

  return buf;
}



static int
cmpstringp(const void *p1, const void *p2) {
  const char* s1 = *(const char**)p1;
  const char* s2 = *(const char**)p2;

  char* e1 = strchr(s1, '='); if (e1 == NULL) fatal("ERROR: Invalid tag as = sign is missing: %s\n", s1);
  char* e2 = strchr(s2, '='); if (e2 == NULL) fatal("ERROR: Invalid tag as = sign is missing: %s\n", s2);

  *e1 = '\0';
  *e2 = '\0';

  int ret = strcoll(s1, s2);

  // Restore
  *e1 = '=';
  *e2 = '=';

  if (ret == 0) {
    return strcoll(e1 + 1, e2 + 1);
  }
  else {
    return ret;
  }
}



void
config_enc(OggOpusEnc* const enc, unsigned bits_per_sample, opus_int32 bitrate) {
  assert(ope_encoder_ctl(enc, OPUS_SET_EXPERT_FRAME_DURATION(OPUS_FRAMESIZE_20_MS))      == OPE_OK &&
         ope_encoder_ctl(enc, OPE_SET_MUXING_DELAY(48000))                               == OPE_OK &&
         ope_encoder_ctl(enc, OPE_SET_COMMENT_PADDING(8192))                             == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_VBR(1))                                           == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_VBR_CONSTRAINT(0))                                == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC))                        == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_APPLICATION(OPUS_APPLICATION_AUDIO))              == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_MAX_BANDWIDTH(OPUS_BANDWIDTH_FULLBAND))           == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_INBAND_FEC(0))                                    == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_COMPLEXITY(10))                                   == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(0))                              == OPE_OK &&
         ope_encoder_ctl(enc, OPUS_SET_DTX(0))                                           == OPE_OK);

  int err = ope_encoder_ctl(enc, OPUS_SET_BITRATE(bitrate));
  if (err != OPE_OK)
    fatal("ERROR: Invalid bitrate: %i %s\n", bitrate, ope_strerror(err));

  err = ope_encoder_ctl(enc, OPUS_SET_LSB_DEPTH(IMAX(8, IMIN(24, bits_per_sample))));
  if (err != OPE_OK)
    fatal("ERROR: Invalid bits_per_sample: %i %s\n", bits_per_sample, ope_strerror(err));
}



void initialize_enc(Data* const d, int empty) {
  assert(d->initialized == 0);
  assert(d->scale       != 0.0);

  int err;

  // Start a new encoding (non-gapless) when
  // - '-i' option is set,
  // - d->prev_scale has not been initialized,
  // - the scaling changes (bitdepth or album gain changed),
  // - but skip the empty FLAC files.
  int resetenc = d->individual || d->prev_scale < 0.0 ||
    (!empty && fabs(d->scale - d->prev_scale) / fmax(d->scale, d->prev_scale) > 0.0001);

  d->comments[d->num_comments++] = my_sprintf("ENCODERSETTINGS=%s %s: bitrate=%i, resetencoder=%i",
    prg, version, d->bitrate, resetenc);

  qsort(d->comments, d->num_comments, sizeof(char*), cmpstringp);

  for (size_t i = 0; i != d->num_comments; ++i) {
    ope_comments_add_string(d->opus_comments, d->comments[i]);

    free(d->comments[i]);
  }

  free(d->comments);

  if (resetenc) {
    if (d->idx != 0) {
      ope_encoder_drain(d->enc);
      ope_encoder_destroy(d->enc);
    }

    d->enc = ope_encoder_create_file(d->out_paths[d->idx], d->opus_comments,
        d->sample_rate, d->channels, 0, &err);
    if (d->enc == NULL || err != OPE_OK)
      fatal("ERROR: %s: %s while initializing encoder\n", d->out_paths[d->idx], ope_strerror(err));

    config_enc(d->enc, d->min_bits_per_sample, d->bitrate);
  }
  else {
    if (d->sample_rate != d->prev_sample_rate)
      fatal("ERROR: Sample rate changed in %s\n",  d->inp_paths[d->idx]);

    if (d->channels    != d->prev_channels)
      fatal("ERROR: Num of channels changed %s\n", d->inp_paths[d->idx]);

    err = ope_encoder_continue_new_file(d->enc, d->out_paths[d->idx], d->opus_comments);
    if (err != OPE_OK)
      fatal("ERROR: %s: %s while encoding\n", d->out_paths[d->idx], ope_strerror(err));
  }

  err = ope_encoder_ctl(d->enc, OPE_SET_SERIALNO(d->serialno));
  if (err != OPE_OK)
    fatal("ERROR: %s: %s while setting serialno\n", d->out_paths[d->idx], ope_strerror(err));

  d->initialized = 1;
}



double
read_gain(const char* const str,
          const regmatch_t  pmatch,
          const Data* const d) {
  assert(pmatch.rm_so != -1);

  const regoff_t len      = pmatch.rm_eo - pmatch.rm_so; assert(len >= 0);
  char* const    gain_str = my_malloc(len + 1);
  memcpy(gain_str, str + pmatch.rm_so, len);
  gain_str[len] = '\0';

  char* endp;
  double gain = strtod(gain_str, &endp);
  if (gain_str == endp)
    fatal("ERROR: %s: Parsing %s\n", d->inp_paths[d->idx], str);

  if (!isfinite(gain))
    fatal("ERROR: %s: %s is not a finite number\n", d->inp_paths[d->idx], str);

  free(gain_str);

  return gain;
}



double
read_env(const char* const env) {
  char* const str = getenv(env);

  if (str == NULL)
    fatal("ERROR: %s env var is not set\n", env);

  char* endp;
  double val = strtod(str, &endp);
  if (str == endp)
    fatal("ERROR: Parsing %s env var\n", env);

  if (!isfinite(val))
    fatal("ERROR: %s env var is not a finite number\n", env);

  return val;
}



// From https://github.com/Moonbase59/loudgain/blob/master/src/tag.cc
int gain_to_q78num(const double gain) {
  // convert float to Q7.8 number: Q = round(f * 2^8)
  return (int) round(gain * 256.0);    // 2^8 = 256
}



FLAC__StreamDecoderWriteStatus
write_cb(const FLAC__StreamDecoder* dec,
         const FLAC__Frame*         frame,
         const FLAC__int32* const   buffer[],
         void*                      data) {
  Data* d = data;

  // Set up the encoder before we write the first frame
  if (frame->header.number.sample_number == 0)
    initialize_enc(d, 0);

  double   scale    = d->scale;
  unsigned channels = d->channels;
  unsigned c        = 0;

  while (c != channels) {
    float*                   o    = d->enc_buffer + c;
    const FLAC__int32*       i    = buffer[c];
    const FLAC__int32* const iend = buffer[c] + frame->header.blocksize;

    while (i != iend) {
      *o = scale * *i;

      o += channels;
      i += 1;
    }

    ++c;
  }

  int err = ope_encoder_write_float(d->enc, d->enc_buffer, frame->header.blocksize);

  if (err != OPE_OK)
    fatal("ERROR: %s: %s\n", d->out_paths[d->idx], ope_strerror(err));

  return FLAC__STREAM_DECODER_WRITE_STATUS_CONTINUE;
}



void
meta_cb(const FLAC__StreamDecoder*  dec,
        const FLAC__StreamMetadata* meta,
        void*                       data) {
  Data* d = data;

  if (meta->type == FLAC__METADATA_TYPE_STREAMINFO) {
    d->scale         = exp(-(meta->data.stream_info.bits_per_sample - 1.0) * M_LN2);
    d->channels      = meta->data.stream_info.channels;
    d->sample_rate   = meta->data.stream_info.sample_rate;

    // To have a semi-random, but repeatable serialno so I can compare opus
    // files w/o decoding.
    memcpy(&(d->serialno), meta->data.stream_info.md5sum, sizeof(opus_int32));
    // To come out in the same byte order:
    d->serialno      = ntohl(d->serialno);
  }
  else if (meta->type == FLAC__METADATA_TYPE_VORBIS_COMMENT) {
    FLAC__StreamMetadata_VorbisComment_Entry* entry     = meta->data.vorbis_comment.comments;
    FLAC__StreamMetadata_VorbisComment_Entry* entry_end = meta->data.vorbis_comment.comments +
      meta->data.vorbis_comment.num_comments;

    // +1 for ENCODERSETTINGS.
    d->comments     = my_malloc(sizeof(char*) * (meta->data.vorbis_comment.num_comments + 1));
    d->num_comments = 0;

    regex_t replaygain_re, album_gain_re, track_gain_re;
    assert(regcomp(&replaygain_re, "^REPLAYGAIN_",                REG_EXTENDED|REG_ICASE) == 0);
    assert(regcomp(&album_gain_re, "^REPLAYGAIN_ALBUM_GAIN=(.*)", REG_EXTENDED|REG_ICASE) == 0);
    assert(regcomp(&track_gain_re, "^REPLAYGAIN_TRACK_GAIN=(.*)", REG_EXTENDED|REG_ICASE) == 0);

    regmatch_t pmatch[2];

    double album_gain = NAN;
    double track_gain = NAN;

    while (entry != entry_end) {
      const char* const comment = (const char*)entry->entry;

      if (regexec(&replaygain_re, comment, 0, NULL, 0)) {
        // Not REPLAYGAIN_*
        d->comments[d->num_comments++] = strndup(comment, entry->length);
  
        if (errno == ENOMEM)
          fatal("ERROR: Out of memory\n");
      }
      else {
        if (!regexec(&album_gain_re, comment, 2, pmatch, 0))
          album_gain = read_gain(comment, pmatch[1], d);

        if (!regexec(&track_gain_re, comment, 2, pmatch, 0))
          track_gain = read_gain(comment, pmatch[1], d);
      }

      ++entry;
    }

    const double limit = 20.0;

    if (d->individual) {
      if (!isnan(track_gain)) {
        if (track_gain < limit) {
          // track_gain uses -18LUFS, but Opus (and me) wants to use -23 LUFS as
          // target loudness.
          d->scale *= exp((track_gain - rg_offset) / 20.0 * M_LN10);
        }
        else
          warning("WARNING: %s: REPLAYGAIN_TRACK_GAIN >= %.1f hence not applied\n",
              d->out_paths[d->idx], limit);
      }
    }
    else {
      if (!isnan(album_gain)) {
        if (album_gain < limit) {
          // album_gain uses -18LUFS, but Opus (and me) wants to use -23 LUFS as
          // target loudness.
          d->scale *= exp((album_gain - rg_offset) / 20.0 * M_LN10);
        }
        else
          warning("WARNING: %s: REPLAYGAIN_ALBUM_GAIN >= %.1f hence not applied\n",
              d->out_paths[d->idx], limit);
      }
    }
    
    regfree(&replaygain_re);
    regfree(&album_gain_re);
    regfree(&track_gain_re);
  }
}



void
error_cb(const FLAC__StreamDecoder*     dec,
         FLAC__StreamDecoderErrorStatus status,
         void*                          data) {
  Data* d = (Data*)data;

  fprintf(stderr, "ERROR: %s: %s\n", d->inp_paths[d->idx],
      FLAC__StreamDecoderErrorStatusString[status]);
}



Data*
ls_flac(char* const inp_dir, char* const out_dir) {
  // Check the out_dir

  struct stat st;
  // Stat follows symbolic links.
  if (stat(out_dir, &st))
    err(EXIT_FAILURE, "ERROR: %s", out_dir);

  if (!S_ISDIR(st.st_mode))
    fatal("ERROR: %s: Not a directory\n", out_dir);

  // Directory does not have to be readable. That is only needed for listing
  // the dir. We do not need to list out_dir.
  if (access(out_dir, W_OK)) {
    if (errno == EACCES)
      fatal("ERROR: %s: Not writable\n", out_dir);
    else
      err(EXIT_FAILURE, "ERROR: %s", out_dir);
  }
  if (access(out_dir, X_OK)) {
    if (errno == EACCES)
      fatal("ERROR: %s: Not executable\n", out_dir);
    else
      err(EXIT_FAILURE, "ERROR: %s", out_dir);
  }

  // Traverse the contents of inp_dir. It is ordered as per current locale.

  struct dirent **list = NULL;
  // Scandir follows symbolic links.
  int size = scandir(inp_dir, &list, NULL, alphasort);
  if (size == -1)
    err(EXIT_FAILURE, "ERROR: %s", inp_dir);

  // Trim tailing slashes on input dirs.

  regex_t slash_re;
  assert(regcomp(&slash_re, "/+$", REG_EXTENDED|REG_ICASE) == 0);
  regmatch_t pmatch[1];

  if(!regexec(&slash_re, inp_dir, 1, pmatch, 0))
    inp_dir[pmatch[0].rm_so] = '\0';
  if(!regexec(&slash_re, out_dir, 1, pmatch, 0))
    out_dir[pmatch[0].rm_so] = '\0';

  regex_t flac_re;
  assert(regcomp(&flac_re, "\\.flac?$", REG_EXTENDED|REG_ICASE) == 0);

  FLAC__StreamMetadata m;
  Data*                d = NULL;

  for (int i = 0; i != size; ++i) {
    if (!regexec(&flac_re, list[i]->d_name, 1, pmatch, 0)) {
      // Matches ".flac?$"

      char* inp_path = my_sprintf("%s/%s", inp_dir, list[i]->d_name);
      int   skip     = 0;

      // Stat follows symbolic links.
      if (stat(inp_path, &st))
        err(EXIT_FAILURE, "ERROR: %s", inp_path);

      if (!S_ISREG(st.st_mode)) {
        warning("WARNING: Skipping %s: Not regular file\n", inp_path);
        skip = 1;
      }
      // Access follows symbolic links.
      else if (access(inp_path, R_OK)) {
        if (errno == EACCES)
          warning("WARNING: Skipping %s: Not readable\n", inp_path);
        else
          err(EXIT_FAILURE, "ERROR: %s", inp_path);

        skip = 1;
      }
      else if (!FLAC__metadata_get_streaminfo(inp_path, &m)) {
        warning("WARNING: Skipping %s: Not a FLAC file\n", inp_path);
        skip = 1;
      }

      if(skip) {
        free(inp_path);
      }
      else {
        // This is a FLAC file.

        // Generate the output path.
        list[i]->d_name[pmatch[0].rm_so] = '\0';
        char* out_path = my_sprintf("%s/%s.opus", out_dir, list[i]->d_name);

        if (access(out_path, F_OK) == 0)
          fatal("ERROR: %s: Path exists\n", out_path);

        if (d == NULL) {
          // This is the 1st FLAC file. Initialize Data.
          d                           = my_malloc(sizeof(Data));

          d->max_blocksize            = m.data.stream_info.max_blocksize;
          d->max_channels             = m.data.stream_info.channels;
          d->min_bits_per_sample      = m.data.stream_info.bits_per_sample;

          d->inp_paths                = my_malloc(sizeof(char*) * size);
          d->out_paths                = my_malloc(sizeof(char*) * size);
          d->inp_paths[0]             = inp_path;
          d->out_paths[0]             = out_path;
          d->num_paths                = 1;

          d->prev_scale               = -1.0;
        }
        else {
          if (d->max_blocksize        < m.data.stream_info.max_blocksize)
              d->max_blocksize        = m.data.stream_info.max_blocksize;

          if (d->max_channels         < m.data.stream_info.channels)
              d->max_channels         = m.data.stream_info.channels;

          if (d->min_bits_per_sample  > m.data.stream_info.bits_per_sample)
              d->min_bits_per_sample  = m.data.stream_info.bits_per_sample;

          d->inp_paths[d->num_paths]  = inp_path;
          d->out_paths[d->num_paths]  = out_path;
          d->num_paths               += 1;
        }
      }
    }
    free(list[i]);
  }
  free(list);

  if (d == NULL)
    fatal("ERROR: %s: No FLAC files found\n", inp_dir);

  if (d->max_channels > max_channels)
    fatal("ERROR: Only mono and stereo are supported\n");

  d->enc_buffer = my_malloc(d->max_channels * d->max_blocksize * sizeof(float));

  regfree(&slash_re);
  regfree(&flac_re);

  return d;
}



void
usage() {
  fprintf(stderr, "%s %s, %s\n\n", prg, version, opus_get_version_string());
  fprintf(stderr, "USAGE: %s [-h] [-w] [-b bitrate] input-dir output-dir\n\n", prg);
  fprintf(stderr, "Encodes all *.fla or *.flac FLAC files from input-dir into OPUS format.\n");
  fprintf(stderr, "The output goes into output-dir with same filename with *.opus extension.\n");
  fprintf(stderr, "Applies (REPLAYGAIN_ALBUM_GAIN - offset) gain if exists, where\n");
  fprintf(stderr, "offset obtained from EBUR128_RG_OFFSET env var, which must be set.\n");
  fprintf(stderr, "It uses GAPLESS encoding between tracks if their gains match.\n\n");
  fprintf(stderr, "  -h   This help.\n");
  fprintf(stderr, "  -w   Do not exit on warnings.\n");
  fprintf(stderr, "  -b   Bitrate in bits/sec. Must be integer (default 160000).\n");
  fprintf(stderr, "  -i   Each track independently encoded (i.e. not gapless), and\n");
  fprintf(stderr, "       applies (REPLAYGAIN_TRACK_GAIN - offset) gain if exists.\n");
}



int main(int argc, char *argv[]) {
  // To make this program locale-aware.
  setlocale(LC_ALL, "");

  prg = basename(argv[0]);

  opus_int32 bitrate      = 140000;
  int        individual   = 0;
  int        c;
  char*      endp;

  while ((c = getopt (argc, argv, "hwb:i")) != -1)
    switch (c) {
      case 'h':
        usage();
        return EXIT_SUCCESS;
        break;

      case 'w':
        exit_warning = 0;
        break;

      case 'b':
        bitrate = (opus_int32)strtoimax(optarg, &endp, 10);
        if (optarg == endp || endp < optarg + strlen(optarg))
          fatal("ERROR: Parsing bitrate = %s\n", optarg);
        break;

      case 'i':
        individual = 1;
        break;

      case '?':
        // Parameter errors. getopt() already prints out an error.
        usage();
        return EXIT_FAILURE;
        break;

      default:
        abort();
    }

  if (argc - optind != 2) {
    if (argc - optind == 0)
      fprintf(stderr, "ERROR: Missing input and output directories\n");
    else if (argc - optind == 1)
      fprintf(stderr, "ERROR: Missing output directory\n");
    else if (argc - optind >  2)
      fprintf(stderr, "ERROR: Too many parameters\n");

    usage();
    return EXIT_FAILURE;
  }

  rg_offset = read_env("EBUR128_RG_OFFSET");

  Data* d = ls_flac(argv[optind], argv[optind + 1]);

  d->bitrate      = bitrate;
  d->individual   = individual;

  for (int i = 0; i != d->num_paths; ++i) {
    d->idx           = i;
    d->initialized   = 0;

    d->opus_comments = ope_comments_create();

    FLAC__StreamDecoder* dec = FLAC__stream_decoder_new();
    assert(dec != NULL);

    FLAC__stream_decoder_set_md5_checking(dec, true);
    FLAC__stream_decoder_set_metadata_respond(dec, FLAC__METADATA_TYPE_VORBIS_COMMENT);

    FLAC__StreamDecoderInitStatus  init_status =
      FLAC__stream_decoder_init_file(dec, d->inp_paths[i], write_cb, meta_cb, error_cb, d);
    if (init_status != FLAC__STREAM_DECODER_INIT_STATUS_OK)
      fatal("ERROR: %s: %s\n", d->inp_paths[i],
          FLAC__StreamDecoderInitStatusString[init_status]);

    if (!FLAC__stream_decoder_process_until_end_of_stream(dec))
      fatal("ERROR: %s: %s\n", d->inp_paths[i],
          FLAC__StreamDecoderStateString[FLAC__stream_decoder_get_state(dec)]);

    if (!d->initialized) {
      // The FLAC file is empty.

      // If the FLAC file is empty, the write_cb() has not been called so 
      // initialize_enc() has not been executed.
      initialize_enc(d, 1);
  
      // We has to run this funtion once (with 0 length), otherwise 
      // ope_encoder_drain() asserts.
      int err = ope_encoder_write_float(d->enc, d->enc_buffer, 0);

      if (err != OPE_OK)
        fatal("ERROR: %s: %s\n", d->out_paths[d->idx], ope_strerror(err));
    }
    else {
      // Only set "prev" values from a non-empty track.
      d->prev_scale       = d->scale;
      d->prev_channels    = d->channels;
      d->prev_sample_rate = d->sample_rate;
    }

    FLAC__stream_decoder_delete(dec);

    ope_comments_destroy(d->opus_comments);

    free(d->inp_paths[i]);
    free(d->out_paths[i]);
  }

  ope_encoder_drain(d->enc);
  ope_encoder_destroy(d->enc);

  free(d->inp_paths);
  free(d->out_paths);
  free(d->enc_buffer);
  free(d);

  return EXIT_SUCCESS;
}
