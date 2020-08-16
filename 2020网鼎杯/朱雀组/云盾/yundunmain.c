int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char *v3; // rsi
  int i; // [rsp+Ch] [rbp-D4h]
  char *fastbin_chunk; // [rsp+10h] [rbp-D0h]
  char *format; // [rsp+18h] [rbp-C8h]
  char s; // [rsp+20h] [rbp-C0h]
  char var_8; // [rsp+21h] [rbp-BFh]
  char v9; // [rsp+22h] [rbp-BEh]
  char v10; // [rsp+23h] [rbp-BDh]
  char v11; // [rsp+24h] [rbp-BCh]
  char v12; // [rsp+25h] [rbp-BBh]
  char v13; // [rsp+26h] [rbp-BAh]
  char v14; // [rsp+27h] [rbp-B9h]
  char dest; // [rsp+60h] [rbp-80h]
  unsigned __int64 v16; // [rsp+C8h] [rbp-18h]

  v16 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  v3 = 0LL;
  setbuf(stderr, 0LL);
  fastbin_chunk = 0LL;
  format = 0LL;
  puts("      Welcome to skShell v0.0.0!");
  puts("-----------------------------------------");
  puts("     Protected by skYunDun v0.0.0 ");
  puts("-----------------------------------------");
  puts("      skYunDun -- Industry leader");
  puts("  We are making this world safer than ever.");
  while ( 1 )
  {
    do
    {
      while ( 1 )
      {
        while ( 1 )
        {
          do
          {
            while ( 1 )
            {
              while ( 1 )
              {
                printf("> ", v3);
                v3 = (_BYTE *)(&dword_30 + 2);
                fgets(&s, 0x32, stdin);
                if ( s == 'l' && var_8 == 's' ) // ls
                  puts("flag\tpwn\t1\t2");
                if ( s == 'c' )
                  break;                        // goto printf format
                if ( s == 'v' )
                {
                  if ( var_8 == 'i' && v9 == 'm' )// vim
                  {
                    puts("------skVim v0.0.0------");
                    if ( v10 == ' ' )
                    {
                      if ( v11 != '1' || v12 != '\n' )
                      {
                        if ( v11 != '2' || v12 != '\n' )
                        {
                          puts("[!] File not exist!");
                        }
                        else                    // vim 2
                        {
                          format = (char *)malloc(0x30uLL);
                          if ( format )
                          {
                            printf("> ", 0x32LL);
                            v3 = format;
                            _isoc99_scanf("%70s", format);
                            puts("Done!");
                          }
                          else
                          {
                            puts("[!] Error! Bad fd detected!");
                          }
                        }
                      }
                      else                      // vim 1
                      {
                        fastbin_chunk = (char *)malloc(0x60uLL);
                        if ( fastbin_chunk )
                        {
                          printf("> ", 0x32LL);
                          v3 = fastbin_chunk;
                          _isoc99_scanf("%70s", fastbin_chunk);
                          puts("Done!");
                        }
                        else
                        {
                          puts("[!] Error! Bad fd detected!");
                        }
                      }
                    }
                    else
                    {
                      puts("[!] Error! Missing an parameter!");
                    }
                  }
                }
                else if ( s == 'r' && var_8 == 'm' && v9 == ' ' )// rm
                {
                  if ( v10 == '1' )
                  {
                    if ( *(fastbin_chunk - 16) )// rm 1
                    {
                      puts(
                        "---------------skYunDun v0.0.0---------------\n"
                        "[!] Detected an heap leak!\n"
                        "[!] Rolling back....");
                      fastbin_chunk = 0LL;
                      format = 0LL;
                    }
                    else
                    {
                      free(fastbin_chunk);
                    }
                  }
                  else if ( v10 == '2' )        // rm 2
                  {
                    free(format);
                  }
                }
              }
              if ( var_8 != 'd' )               // change dir
                break;
              if ( v9 == ' ' )
              {
                v3 = &v10;
                strcpy(&dest, &v10);
                changedir(&dest);
              }
            }
          }
          while ( var_8 != 'a' || v9 != 't' || v10 != ' ' );// at
          if ( v11 != '1' )
            break;
          if ( fastbin_chunk )                  // at 1
            puts(fastbin_chunk);
        }
        if ( v11 == '2' )                       // at 2
          break;
        if ( v11 != 'f' || v12 != 'l' || v13 != 'a' || v14 != 'g' )
        {
          if ( v11 != 'p' || v12 != 'w' || v13 != 'n' )
            puts("[!] No such file!");
          else
            puts("[!] Cannot view a binary file!");
        }
        else
        {
          puts("[!] This file is protected by skYunDun");
        }
      }
    }
    while ( !format );
    for ( i = 0; ; ++i )
    {
      if ( i >= strlen(format) )
        goto LABEL_27;
      if ( format[i] == '%' && format[i + 1] == 'n'
        || format[i] == '%' && format[i + 1] == 'h'
        || format[i] == '%' && format[i + 1] == 'x' )
      {
        break;
      }
    }
    puts("---------------skYunDun v0.0.0---------------\n[!] Detected an format attack!\n[!] Rolling back....");
    *format = 0;
LABEL_27:
    printf(format, 0x32LL);
    putchar(10);
  }
}