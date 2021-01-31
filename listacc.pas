$Standard_Level 'EXT_MODCAL'$
$COPYRIGHT_DATE '1993'$
$tables ON$
$RANGE OFF$
$OPTIMIZE ON$

Program LISTACC (Input, Output, Info );

{***************************************************************************}
{ Title         : LISTACC4                                                  }
{ Date          : July 26, 1993                                             }
{ Programmer    : Greg F                                                    }
{ Company       :                                                           }
{                                                                           }
{                                                                           }
{ MPE Version   : MPE XL User Version B.40.00                               }
{ Description   : LISTACC will list a fileset's accessors. Specifically,    }
{                 for each process accessing a file, it will list:          }
{                    1) Program name                                        }
{                    2) Job/session number                                  }
{                    3) Its PIN number                                      }
{                    4) Its corresponding Jobname, User name & Account name }
{                    5) The number of reads, writes, and the current        }
{                       position of the file pointer                        }
{                                                                           }
{                 LISTACC can only give limited information on circular,    }
{                 LISTACC is adapted from SHOWACC written by                }
{                 John Sullivan of INTEREX.                                 }
{***************************************************************************}
{ MODS:           3/1/95:  Add check for STORE/RESTORE for files that       }
{                          are not opened.  Guy S                           }
{***************************************************************************}

TYPE
  status_type                =
     record
        case boolean of
          true               : (all   : integer);
          false              : (info  : shortint;
                                subsys: shortint);
     end;

  itemnum_array_type         = array [1..10] of integer;
  item_array_type            = array [1..10] of globalanyptr;
  status_array_type          = array [1..10] of status_type;

CONST

  max_num_pids  =  5;            { Get PIDS in groups of this value }
  max_num_files =  512;          { Get files in groups of this value }

  init_itemnum_array         = itemnum_array_type [10 of 0];
  init_item_array            = item_array_type [10 of Nil];
  init_status_type           = status_type [info : 0, subsys : 0];
  init_item_status_array     = status_array_type [10 of init_status_type];

  process_aif_area =  2000;
  file_aif_area = 5000;

Type

  bit2                       = 0..3;
  bit8                       = 0..255;
  bit14                      = 0..16383;
  string255                  = string[255];
  String60                   = String[60];
  String7                    = String[7];
  pac16                      = packed array[1..16] of char;


  directory_name_type = record
     user : packed array [1..16] of char;
     group : packed array [1..16] of char;
     account : packed array [1..16] of char;
     end;

  os_version                 = (all, buggy, correct);

  js_num_type                =
     packed record
       case os_tag: os_version of
         all               : (all    : integer);
         correct           : (js_type1: bit2;
                              js_num1 : bit14;
                              js_ext1 : shortint);
         buggy             : (js_ext : shortint;
                              js_type: bit2;
                              js_num : bit14);
     end;

  longint_type               =
    packed record
      case boolean of
        TRUE : ( long : longint );
        FALSE: ( sep  : RECORD
           left                   : integer;
           right                  : integer;
               END ) ;
    end;

  ufid_type                  =
    record
      ufid                   : packed array [1..20] of char;
    end;

  file_name_type             =
    record
      filename               : packed array [1..16] of char;
      group                  : packed array [1..16] of char;
      account                : packed array [1..16] of char;
    end;


  search_key_type = record
     case integer of
        1: (key_js_num : integer);
        2: (key_pid    : longint_type);
        3: (key_ufid   : ufid_type);
        4: (key_fname  : file_name_type);
        5: (key_dname  : directory_name_type);
        6: (key_sfnum  : integer);
        7: (key_portid : integer);
        8: (key_portnm : pac16);
        9: (key_plfd   : localanyptr);
        10:(key_js_ind : integer);
        11:(key_pid_ind: integer);
     end;

   bit_integer_type = PACKED RECORD
            b1_8, b9_16                     : 0..255;
            b17,b18,b19,b20,b21,b22,b23,b24 : 0..1;
            b25_32                          : 0..255;
   end;

   kind_file_type = ( regular, circular, message, rio, storing, restoring );

VAR

  some_file_accessed,
  first_time,
  empty_fileset,
  dont_call_get_pids,
  Is_interactive             : Boolean;

  kind_file                  : kind_file_type;

  job_number                 : string[5];
  js_number_disp             : string[7];
  user_disp                  : string[26];
  program_string,
  file_name_disp             : string60;
  infostring,hold_infostring : string255;

  ct,
  max_files,
  User_Id,
  i,
  user_label_number,
  record_size,
  file_eof_bytes,
  file_limit_bytes,
  file_eof,
  file_limit,
  record_pointer,
  disp_read,
  disp_written,
  disp_pointer,
  total_pids                 : integer;

  foptions                   : bit_integer_type;

  overall_status             : status_type;                {4 bytes}
  js_number_buggy            : js_num_type;

  pid,
  read_value_long,
  written_value_long         : longint_type;               {8 bytes}

  pid_pac                    : packed array [1..4] of char;
  user_name                  : packed array [1..16] of char;
  user_account_name          : packed array [1..16] of char;
  user_js_name               : Packed array [1..16] of char;
  info                       : packed array [1..80] of char;

  ufid_file_name             : ufid_type;                  {20 bytes}

  itemnum_array              : itemnum_array_type;         {40 bytes}
  item_array                 : item_array_type;            {40 bytes?}
  itemstatus_array           : status_array_type;          {40 bytes}
  pid_array                  : array [1..max_num_pids] of longint_type; {40}

  search_key,
  p_search_key               : search_key_type;            {48 bytes}
  filename_rec,
  check_filename_rec,
  orig_filename_rec,
  program_name               : file_name_type;             {48 bytes}

  fnum_array                 : array [1..max_num_files] of integer;{2048 bytes}

  filesetarray               : array [1..max_num_files] of file_name_type;

Procedure GETPRIVMODE        ; Intrinsic;
Procedure FPARSE             ; Intrinsic;
Procedure WHO                ; Intrinsic;
Procedure GETUSERMODE        ; Intrinsic;
Procedure HPCIGETVAR         ; Intrinsic;
Procedure HPERRMSG           ; Intrinsic;
PROCEDURE XCONTRAP           ; INTRINSIC;
procedure terminate          ; intrinsic;
procedure dascii             ; intrinsic;

$SYSINTR 'AIFINTR.PUB.SYS'$
Procedure AIFPROCGET         ; Intrinsic;
Procedure AIFJSGET           ; Intrinsic;
Procedure AIFFILELGET        ; Intrinsic;
Procedure AIFFILEGGET        ; Intrinsic;
Procedure AIFSYSWIDEGET      ; Intrinsic;
procedure AIFGLOBINSTALL     ; intrinsic;

procedure sr_scan_nm(   var ufid:     ufid_type;
                        var status:   status_type);  external;

procedure ctrl_y;
   begin
   writeln('< Control-Y >', #10);
   terminate;
   end;

PROCEDURE CTRL_Y_HANDLER ( PROCEDURE P );
VAR plabel,
    oldplabel : INTEGER;

   BEGIN
   plabel := WADDRESS(P);
   XCONTRAP(plabel, oldplabel);
   END;

FUNCTION num_digits ( i : integer ) : integer;
BEGIN
   CASE i OF
      0..9 : num_digits := 1;
      10..99 : num_digits := 2;
      100..999 : num_digits := 3;
      Otherwise   num_digits := 4;
   END;
END;

FUNCTION Is_HPInteractive : BOOLEAN;
VAR
  keyword     : integer;
  keyword2    : integer;
  length      : integer;
  status      : integer;
  hpvar       : packed array [1..15] of char;
  interactive : integer;
  jobtype     : string[2];

BEGIN
   hpvar    := 'HPINTERACTIVE ';
   keyword  := 3;
   hpcigetvar( hpvar, status, keyword, interactive );
   if ( status <> 0 ) then
      WRITELN( 'hpciget failed err = ', status );

   hpvar    := 'HPJOBTYPE ';
   keyword  := 2;
   keyword2 := 11;
   hpcigetvar( hpvar, status, keyword, jobtype, keyword2, length );
   setstrlen( jobtype, length );
   if ( status <> 0 ) then
      WRITELN( 'hpciget failed err = ', status );

  Is_HPInteractive := ( Jobtype = 'S' ) AND ( Interactive = 1 );
END;

$page$
Procedure error_routine (call : String60; error_code: status_type;
                         error_array: status_array_type);
begin

    writeln (call, ' Error: info: ', error_code.info:1,
              ' subsys: ',     error_code.subsys:1);

    HPERRMSG (2,
               ,
               ,
              error_code);

    if (error_code.info > 0) then
      begin

        writeln ('Error: info: ', error_array[error_code.info].info:1,
                ' subsys: ',     error_array[error_code.info].subsys:1);

        hperrmsg(2,,,error_array[error_code.info]);

      end;

end;

function is_fileset : boolean;
begin
   is_fileset :=
      ((strpos(hold_infostring, '@') > 0) OR
       (strpos(hold_infostring, '#') > 0) OR
       (strpos(hold_infostring, '?') > 0) OR
       (strpos(hold_infostring, '[') > 0));
end;


$page$
Procedure clear_stat;
begin

   itemstatus_array := init_item_status_array;
   itemnum_array    := init_itemnum_array;
   item_array       := init_item_array;
   overall_status   := init_status_type;

end;
$page$
Function  do_install: boolean;
begin

  do_install := FALSE;

  clear_stat;

  getprivmode;

  AIFGLOBINSTALL ( overall_status, User_id);

  getusermode;

  if overall_status.all <> 0 then
    begin

      clear_stat;

      writeln('AIFGLOBINSTALL Failed! Cannot recover');

    end

   else

     do_install := TRUE;

end;



$page$
Function  get_ufid_list:  boolean;
begin

     get_ufid_list := FALSE;

     fnum_array[1] := 512;
     clear_stat;

     itemnum_array[1] := 2063;   { file #'s of open files process has open }
     itemnum_array[2] := 2015;   { job/session # to which process belongs }
     itemnum_array[3] := 2034;   { program name }

     item_array[1] := addr(fnum_array);
     item_array[2] := addr(js_number_buggy.all);
     item_array[3] := addr(program_name);

     getprivmode;

     AIFPROCGET   (overall_status,
                   itemnum_array,
                   item_array,
                   itemstatus_array,
                   ,
                   pid
                  );

     getusermode;

     If overall_status.all <> 0 then
       if NOT ( overall_status.info IN [ -28, -29, -30 ] )  then
          error_routine ('Get_ufid_list', overall_status, itemstatus_array)
       else
     else
       get_ufid_list := TRUE;

end;

Function  get_file_info: boolean;
var cm_flag : boolean;
    i,a     : integer;
begin

  get_file_info := FALSE;

  disp_read := 0;
  disp_written := 0;
  disp_pointer := 0;

  a := fnum_array[1] + 1;
  i := 2;

  while ( i <= a ) do

    begin

      clear_stat;

      itemnum_array[1] := 4001;  { filename }
      itemnum_array[2] := 4018;  {  # logical reads (NM files ) }
      itemnum_array[3] := 4019;  {  # logical writes   "        }
      itemnum_array[4] := 4011;  {  rec number }
      itemnum_array[5] := 4024;  {  is CM file? }

      item_array[1]    := addr(check_filename_rec);
      item_array[2]    := addr(read_value_long);
      item_array[3]    := addr(written_value_long);
      item_array[4]    := addr(record_pointer);
      item_array[5]    := addr(cm_flag);

      getprivmode;

      AIFFILELGET (overall_status,
                  itemnum_array,
                  item_array,
                  itemstatus_array,
                  fnum_array[i],
                  pid);            { get info about particular process }
                                   { opening this file }

     getusermode;

     If (overall_status.all <> 0) and
       ((overall_status.info <> 13) and (overall_status.subsys <> 109)) THEN
       begin

         if not cm_flag then
           begin

             error_routine('Get_file_info', overall_status, itemstatus_array);
             i:= 65535;

           end

         else

           i := i + 1;

       end
     else
       begin
          { Same process could have file open more than once! }
          if (check_filename_rec.filename = filename_rec.filename) and
             (check_filename_rec.group = filename_rec.group) and
             (check_filename_rec.account = filename_rec.account) then
            begin

              get_file_info := TRUE;

              disp_written := disp_written + written_value_long.sep.right;
              disp_read := disp_read + read_value_long.sep.right;
              if (record_pointer > disp_pointer) then
                 disp_pointer := record_pointer;

            end;

         i := i + 1;

       end;

   end;  { while loop }

end;

$page$
Function  get_js_info:  boolean;
begin

     get_js_info := FALSE;

     clear_stat;

     itemnum_array[1] := 1009; { obvious }
     itemnum_array[2] := 1011;
     itemnum_array[3] := 1001; { job name }

     item_array[1]    := addr(user_name);
     item_array[2]    := addr(user_account_name);
     item_array[3]    := addr(user_js_name);

     getprivmode;

     AIFJSGET     (overall_status,
                   itemnum_array,
                   item_array,
                   itemstatus_array,
                   js_number_buggy.all
                  );

     If overall_status.all <> 0 then
       IF overall_status.info = -28 THEN
          BEGIN
          get_js_info := TRUE;
          user_name := 'Unavail';
          user_account_name := 'Unavail';
          user_js_name := 'Unavail';
          END
       ELSE
          error_routine ('Get_js_info', overall_status, itemstatus_array)
     else
       get_js_info := TRUE;

end;


$page$
Function  get_pids: boolean;
begin

  get_pids := FALSE;

  clear_stat;

  itemnum_array[1] := 2065;  { all processes accessing specified file ! }

  item_array[1]    := addr(ufid_file_name.ufid);

  total_pids := max_num_pids;

  getprivmode;

  AIFSYSWIDEGET(overall_status,
                process_aif_area,
                pid_array,
                ,
                total_pids,
                itemnum_array,
                item_array,
                itemstatus_array,
                p_search_key
                );

  getusermode;

  if (overall_status.all <> 0) then

     error_routine ('Get_pids', overall_status, itemstatus_array)

  else

  if (total_pids in [1..max_num_pids - 1]) then
        begin
        get_pids := TRUE;
        if p_search_key.key_pid.sep.left = 0 then
           dont_call_get_pids := true;
        end

  ELSE
     IF total_pids = max_num_pids THEN  { either found 0 or => max }
        IF p_search_key.key_pid.sep.left <> 0 THEN      {found pids !}
           get_pids := TRUE;


end;

$page$
Function  verify_file_name: boolean;
type vector_type =
  packed record
    offset       : shortint;
    length       : shortint;
  end;

var fparse_items : packed array[1..10] of shortint;
    fparse_result: packed array[1..2] of shortint;
    fparse_vector: packed array[1..10] of vector_type;
    filename     : packed array[1..50] of char;

begin

  verify_file_name := FALSE;
  filename := ' ';

  fparse_items[1] := 1;
  fparse_items[2] := 3;
  fparse_items[3] := 4;
  fparse_items[4] := 0;

  strmove(strlen(infostring),infostring,1,filename,1);

  fparse(filename,fparse_result,fparse_items,fparse_vector);

  if (fparse_result[1] <> 0) then
    begin

        writeln;

        case fparse_result[1] of

         -3: writeln('Illegal delimiter');
         -7: writeln('Unidentified system file');
         -8: writeln('Lockword not allowed');
         -101: writeln('First character not alphabetic');
         -102: writeln('File name expected');
         -103: writeln('File name too long');
         -104: writeln('First character in lockword not alphabetic');
         -105: writeln('Lockword expected');
         -106: writeln('Lockword too long');
         -107: writeln('First character in group not alphabetic');
         -108: writeln('Group name expected');
         -109: writeln('Group name too long');
         -110: writeln('First character in account not alphabetic');
         -111: writeln('Account name expected');
         -112: writeln('Account name too long');
         1..6: writeln('System file not allowed');
         otherwise writeln('File name invalid');

         end;
         Writeln;

    end
  else

      verify_file_name := TRUE;


end;

$page$

PROCEDURE FILL_STR_WITH_PROG_NAME ( VAR p_str : String60;
                                    Prog_Name : File_name_type );

BEGIN
   setstrlen(p_str,0);

   strmove(16,Prog_Name.filename,1,p_str,1);
   p_str := strrtrim(p_str) + '.';

   strmove(16,Prog_Name.group,1,p_str,strlen(p_str)+1);
   p_str := strrtrim(p_str) + '.';

   strmove(16,Prog_Name.account,1,p_str,strlen(p_str)+1);

   p_str := strrtrim(p_str);

   if (strlen(p_str) > 26) then
      setstrlen(p_str,26)
   else
      strappend(p_str,strrpt(' ',26-strlen(p_str)));

END;

$page$
procedure CheckStore(        ufid:     ufid_type;
                        var  store:    boolean;
                        var  restore:  boolean);

var
  status:          status_type;

begin
  store  :=FALSE;
  restore:=FALSE;
  GetPrivMode;
  sr_scan_nm(ufid,status);
  GetUserMode;
  if status.all = hex ('100d1') then store  :=TRUE;
  if status.all = hex ('200d1') then restore:=TRUE;
end;


$page$
Function  get_ufid_name: boolean;

var
  store, restore:  boolean;

Procedure Show_Access(kind_file:kind_file_type);
VAR
  num_readers, num_writers, num_openers : Integer;
Begin

  clear_stat;

  itemnum_array[1] := 5026;
  itemnum_array[2] := 5027;
  itemnum_array[3] := 5025;
  item_array[1] := addr(num_readers);
  item_array[2] := addr(num_writers);
  item_array[3] := addr(num_openers);

  GetPrivMode;

  AIFFILEGGET(overall_status,itemnum_array,item_array,itemstatus_array,
              ufid_file_name);

  GetUserMode;

  if (overall_status.all <> 0) then
     error_routine ('Show_Access', overall_status, itemstatus_array)

  ELSE
     IF (num_openers > 0) or (num_readers > 0) or (num_writers > 0) or store or restore THEN
        BEGIN
        some_file_accessed := TRUE;
        Writeln;
        IF kind_file = storing  then
           Writeln(program_string, ' is being STOREd: ') else
        IF kind_file = restoring  then
           Writeln(program_string, ' is being RESTOREd: ') else
        IF kind_file = Circular then
           Write(program_string, ' is a circular file: ') else
        IF kind_file = Message THEN
           Write(program_string, ' is a message file: ') else
           Write(program_string, ' is a relative I/O file: ');
        if not((kind_file=storing) or (kind_file=restoring)) then
           Writeln(num_readers:num_digits(num_readers), ' readers, ',
                   num_writers:num_digits(num_writers), ' writers, ',
                   num_openers:num_digits(num_openers), ' openers.');
        END;

End;

begin

  get_ufid_name := FALSE;

  kind_file := regular;
  filename_rec := filesetarray[ct];
  clear_stat;

  itemnum_array[1] := 5002;  { ufid }
  itemnum_array[2] := 5017;  { eof }
  itemnum_array[3] := 5018;  { file limit }
  itemnum_array[4] := 5019;  { number user labels }
  itemnum_array[5] := 5016;  { record size (bytes) }
  itemnum_array[6] := 5012;  { Foptions }

  item_array[1]    := addr(ufid_file_name);
  item_array[2]    := addr(file_eof_bytes);
  item_array[3]    := addr(file_limit_bytes);
  item_array[4]    := addr(user_label_number);
  item_array[5]    := addr(record_size);
  item_array[6]    := addr(foptions);

  getprivmode;


  AIFFILEGGET(overall_status,
              itemnum_array,
              item_array,
              itemstatus_array,
              ,
              filename_rec,
              );

  getusermode;

  if (overall_status.all <> 0) then

     error_routine ('get_ufid_name', overall_status, itemstatus_array)

  else

     BEGIN
     WITH foptions DO
        BEGIN
        if ((b19 = 1) and (b20 = 1) and (b21 = 0)) then
           kind_file := message else
        if ((b19 = 1) and (b20 = 0) and (b21 = 0)) then
           kind_file := circular else
        if ((b19 = 0) and (b20 = 1) and (b21 = 0)) then
           kind_file := rio;
        END;

     CheckStore(ufid_file_name,store,restore);
     if store=TRUE   then kind_file:=storing;
     if restore=TRUE then kind_file:=restoring;

     IF kind_file <> regular THEN
        BEGIN
        FILL_STR_WITH_PROG_NAME ( program_string, filename_rec );
        program_string := STRRTRIM(program_string);
        SHOW_ACCESS(kind_file);
        END
     ELSE
         get_ufid_name := TRUE;
     END;

end;

Procedure PRINT_HORIZONTAL_LINE;

BEGIN

   IF Is_Interactive THEN
      BEGIN
         Write ( Chr ( 14 ) );
         writeln(strrpt(',', 79));
      END
   ELSE
         writeln(strrpt('_',79), #10);
END;

$page$
Procedure write_header;
begin

   setstrlen(file_name_disp,0);

   strmove(16,filename_rec.filename,1,file_name_disp,1);
   file_name_disp := strrtrim(file_name_disp) + '.';

   strmove(16,filename_rec.group,1,file_name_disp,strlen(file_name_disp)+1);
   file_name_disp := strrtrim(file_name_disp) + '.';

   strmove(16,filename_rec.account,1,file_name_disp,strlen(file_name_disp)+1);
   file_name_disp := strrtrim(file_name_disp);

   if (strlen(file_name_disp) > 32) then
      setstrlen(file_name_disp,32)
   else
      strappend(file_name_disp,strrpt(' ',32-strlen(file_name_disp)));

   file_eof := (file_eof_bytes - (256*user_label_number)) DIV record_size;

   file_limit := (file_limit_bytes - (256*user_label_number)) DIV record_size;

   writeln(#10, 'For file: ', file_name_disp,
           'EOF=', file_eof,
           '  LIMIT=', file_limit);

   PRINT_HORIZONTAL_LINE;

   writeln('Program               ',
           'Jobnum PIN ',
           'Job/Session,User.Acct    ',
           'Reads  ',
           'Writes ',
           'Pointer', #10);

end;

$page$
Procedure list_file_info;
var t                : integer;
begin

   some_file_accessed := TRUE;

   FILL_STR_WITH_PROG_NAME ( program_string, program_name );

   IF js_number_buggy.js_num1 = 0 then
      begin
      js_number_disp := 'None   ';
      user_disp :=      'None                  ';
      end
   else
   begin
   if (js_number_buggy.js_type1 = 1) then  { was 'correct' }
     js_number_disp := '#S'
   else
     js_number_disp := '#J';

   strwrite(job_number,1,t,js_number_buggy.js_num1:5);
   job_number := strltrim(job_number);
   strmove(strlen(job_number), job_number, 1, js_number_disp, 3);
   strappend(js_number_disp, strrpt(' ', 7-strlen(js_number_disp)));

   setstrlen(user_disp,0);

   if user_js_name[1] <> ' ' then
      begin
      strmove(8, user_js_name, 1, user_disp, 1);
      user_disp := strrtrim(user_disp) + ',';
      end;

   strmove(8,user_name,1,user_disp,strlen(user_disp)+1);
   user_disp := strrtrim(user_disp) + '.';
   strmove(8,user_account_name,1,user_disp,strlen(user_disp)+1);
   user_disp := strrtrim(user_disp);

   strappend(user_disp,strrpt(' ',26-strlen(user_disp)));
   end;

   pid_pac := ' ';
   DASCII ( pid.sep.left, 10, pid_pac );

   If disp_read > 99999999 THEN
      disp_read := -1;
   If disp_written > 99999999 THEN
      disp_written := -1;
   If disp_pointer > 99999999 THEN
      disp_pointer := -1;

   writeln(program_string : 21, ' ',
           js_number_disp ,
           pid_pac        ,
           user_disp      : 22,
           disp_read      : 8,
           disp_written   : 8,
           disp_pointer   : 8);

end;

$page$
Procedure write_footer;
begin

   PRINT_HORIZONTAL_LINE;
   writeln;

end;

Procedure write_footer2;
begin
   IF not some_file_accessed THEN
    IF NOT empty_fileset THEN
      IF is_fileset THEN
         writeln(#10,'No files in ', hold_infostring, ' are being accessed',#10)
      ELSE
         writeln(#10, hold_infostring, ' is not being accessed', #10);
end;

function search_key_filled : boolean;
   begin
      search_key_filled := ( search_key.key_fname.filename <> ' ' );
   end;

procedure clear_search_key ( VAR s_key : search_key_type );
begin
   with s_key DO
      begin
      key_js_num := 0;
      key_pid.sep.left := 0;
      key_pid.sep.right := 0;
      key_ufid.ufid := ' ';
      key_fname.filename := ' ';
      key_fname.group := ' ';
      key_fname.account := ' ';
{     key_sfnum := 0;
      key_portid := 0;
      key_portnm := ' ';
      key_js_ind := 0;
      key_pid_ind := 0;
      key_dname.user := ' ';
      key_dname.group := ' ';
      key_dname.account := ' ';
      key_plfd := NIL;
}     end;
end;

procedure clear_p_search_key ( VAR s_key : search_key_type );
begin
   with s_key DO
      begin
      key_js_num := 0;
      key_pid.sep.left := 0;
      key_pid.sep.right := 0;
{     key_ufid.ufid := ' ';
      key_fname.filename := ' ';
      key_fname.group := ' ';
      key_fname.account := ' ';
      key_sfnum := 0;
      key_portid := 0;
      key_portnm := ' ';
      key_js_ind := 0;
      key_pid_ind := 0;
      key_dname.user := ' ';
      key_dname.group := ' ';
      key_dname.account := ' ';
      key_plfd := NIL;
}     end;
end;
function get_fileset_array : boolean;
begin
   get_fileset_array := false;
   CLEAR_STAT;
   itemnum_array[1] := 5001;
   item_array[1] := ADDR(orig_filename_rec);
   max_files := max_num_files;
   GETPRIVMODE;

   AIFSYSWIDEGET(overall_status,
                 file_aif_area,
                 ,
                 filesetarray,      {Would rather get the fileset array}
                 max_files,         {instead of the UFID array because}
                 itemnum_array,     {UFID can change over time}
                 item_array,
                 itemstatus_array,
                 search_key);

   GETUSERMODE;

   IF (overall_status.all <> 0) THEN
      error_routine('get_ufid_list', overall_status, itemstatus_array)
   ELSE
   IF max_files > 0 tHEN
      begin
      if (max_files < max_num_files) then
      if is_fileset then
      writeln('Processing ', max_files:num_digits(max_files), ' files ...')
      else
      else
      writeln('Processing ', max_files:num_digits(max_files), '+ files ...');

      get_fileset_array := TRUE;
      end
   else
      IF first_time THEN { because of filesets multiples of max_num_files }
         begin
         empty_fileset := true;
         if is_fileset then
            writeln('No files found in ', hold_infostring)
         else
            writeln(hold_infostring, ' doesn''t exist');
         writeln;
         end;

  first_time := false;
end;

Procedure ShowHelp;
BEGIN
Writeln('LISTACC shows you what is accessing a fileset.', #10);
Writeln('Usage:  LISTACC <fileset>', #10);
Writeln('NOTES:');
Writeln('    LISTACC can only give you limited information on circular,');
Writeln('       message, and relative I/O files.');
Writeln('    A value of -1 for Reads, Writes, or Pointer indicates its value');
Writeln('       is too large to be displayed on the line.');
Writeln('    LISTACC is adapted from the CSL program SHOWACC, written by');
Writeln('       John Sullivan of INTEREX.', #10);
TERMINATE;

END;

FUNCTION INPUT_FILE_OK : BOOLEAN;
var file_ok : boolean;

Procedure upshift (VAR c: string255);
var t, i: shortint;
begin

    i:=1;
    t:= strlen(c);

    while i <= t do
      begin

       if (c[i] > #96) and (c[i] < #123) then
         c[i] := chr(ord(c[i]) - 32)
       else
       if (c[i] = #00) then c[i] := ' ';
       i:=i+1;

      end;

end;

   BEGIN

   IF Info = '?' THEN
      ShowHelp;
   file_ok := true;
   if info <> ' ' then
      strmove(80, info, 1, infostring, 1)
   else
      begin
      prompt ('Enter fileset: ');
      readln(infostring);
      end;
   infostring := strrtrim(infostring);
   infostring := strltrim(infostring);

   upshift(infostring);
   hold_infostring := infostring;
   if (is_fileset) Then
      if (strpos(hold_infostring, '[')>0) OR (strpos(hold_infostring, ']')>0)
         then begin
         writeln('Sorry, fileset ranges are not yet supported');
         file_ok := false;
         end
      else
   else
      if not ( verify_file_name ) then
         file_ok := false;
   if file_ok then
   begin
   with filename_rec do
         begin
         filename := '';
         group := '';
         account := '';
         end;
   if strpos ( infostring, '.') > 0 then
     begin
     strmove(strpos(infostring,'.')-1,infostring,1, filename_rec.filename,1);
     strdelete(infostring, 1, strpos(infostring, '.'));
     end
   else
     begin
     strmove(strlen(infostring), infostring, 1, filename_rec.filename,1);
     strdelete(infostring, 1, strlen(infostring));
     end;

   if strpos ( infostring, '.') > 0 then
     begin
     strmove(strpos(infostring, '.')-1, infostring, 1, filename_rec.group,1);
     strdelete(infostring, 1, strpos(infostring, '.'));
     if strlen(infostring) > 0 then
        strmove(strlen(infostring), infostring, 1, filename_rec.account, 1);
     end
   else
     if strlen(infostring) > 0 then
        strmove(strlen(infostring), infostring, 1, filename_rec.group, 1);

   orig_filename_rec := filename_rec;

   end; { file ok }
   input_file_ok := file_ok;
   END;

FUNCTION IS_VERSION_4 : Boolean;
VAR
   Pac_User_Ver : Packed Array [1..8] of char;
Procedure AIFSCGET           ; Intrinsic;
BEGIN

   Clear_stat;

   Itemnum_array[1] := 3058;       { User Version id - avail only on Ver 4}
   Item_array[1] := addr(Pac_User_Ver);

   GetPrivMode;

   AIFSCGET (overall_status, itemnum_array, item_array, itemstatus_array);

   GetUserMode;

   IF (overall_status.all <> 0) THEN
      IF (itemstatus_array[1].subsys<>516) or (itemstatus_array[1].info<>-3001)
      THEN error_routine('Is_Version_4', overall_status, itemstatus_array);

   IS_VERSION_4 := overall_status.all = 0;
END;

PROCEDURE INIT_VARS;

BEGIN
   User_Id  := 1229870168; {The AIF User id - You must fill this in to compile}
   some_file_accessed := FALSE;
   first_time := TRUE;
   empty_fileset := false;
   Is_Interactive := Is_HPInteractive;
END;

$page$
{main line}

Begin

   writeln(
'LISTACC: Show a fileset''s accessors.     (c) 1993');
   Writeln(
'         (Version MPE4.060693) Type LISTACC ? for help. Hit Ctrl-Y to halt.');
   writeln;

   INIT_VARS;

   IF NOT IS_VERSION_4 THEN Writeln(
  'WARNING: This version of LISTACC intended for MPE XL version 4 or greater.',
  #10);

   if do_install then
     begin
     ctrl_y_handler ( ctrl_y );
     clear_search_key( search_key );
     if input_file_ok then
        begin
        REPEAT

        if get_fileset_array then
           for ct := 1 to max_files do

              if get_ufid_name then
               { file id number }
                 begin
                 dont_call_get_pids  := FALSE;
                 clear_p_search_key( p_search_key );
                 if get_pids then
                 { all pids opening file }
                    begin
                      write_header;
                      REPEAT
                      i := 1;
                      while (i <= total_pids) do
                        begin
                          pid := pid_array[i];
                          i := i + 1;
                          if get_ufid_list and
                           { gets info on associated jobs (program name ..) }
                             get_file_info and
                           { gets # reads, writes, file pointer }
                             get_js_info then
                           { gets user name and account name }

                              list_file_info;

                        end;
                      UNTIL (( dont_call_get_pids ) OR ( NOT get_pids ));
                     write_footer;
                    end;
               end;
           UNTIL NOT ( search_key_filled );
           write_footer2;
           END;
   end;

end
