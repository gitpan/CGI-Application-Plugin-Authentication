use Module::Build;

Module::Build->new(
    module_name => 'CGI::Application::Plugin::Authentication',
    license => 'perl',
    requires => {
        'CGI::Application' => 4,
        'Scalar::Util' => 0,
        'Class::ISA' => 0,
        'UNIVERSAL::require' => 0,
    },
    recommends => {
        'CGI::Cookie' => 0,
        'MIME::Base64' => 0,
        'Digest::MD5' => 0,
        'Digest::SHA1' => 0,
        'CGI::Application::Plugin::Session' => 0,
    },
    build_requires => {
        'Test::More' => 0,
        'Test::Exception' => 0,
    },
    create_makefile_pl => 'traditional',
    dist_author => 'Cees Hek <ceeshek@gmail.com>',
)->create_build_script;

