package test_utils

const SERVER_CONFIG = `
autoexec:
version:
  name: velociraptor
  version: 0.6.4-rc4
  commit: f3264824
  build_time: "2022-04-14T02:23:05+10:00"
Client:
  server_urls:
  - https://localhost:8000/
  ca_certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDTDCCAjSgAwIBAgIRAJH2OrT69FpC7IT3ZeZLmXgwDQYJKoZIhvcNAQELBQAw
    GjEYMBYGA1UEChMPVmVsb2NpcmFwdG9yIENBMB4XDTIxMDQxMzEwNDY1MVoXDTMx
    MDQxMTEwNDY1MVowGjEYMBYGA1UEChMPVmVsb2NpcmFwdG9yIENBMIIBIjANBgkq
    hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLO3/Kq7RAwEhHrbsprrvCsE1rpOMQ6Q
    rJHM+0zZbxXchhrYEvi7W+Wae35ptAJehICmbIHwRhgCF2HSkTvNdVzSL9bUQT3Q
    XANxxXNrMW0grOJwQjFYBl8Bo+nv1CcJN7IF2vWcFpagfVHX2dPysfCwzzYX+Ai6
    OK5MqWwk22TJ5NWtUkH7+bMyS+hQbocr/BwKNWGdRlP/+BuUo6N99bVSXqw3gkz8
    FLYHVAKD2K4KaMlgfQtpgYeLKsebjUtKEub9LzJSgEdEFm2bG76LZPbKSGqBLwbv
    x+bJcn23vb4VJrWtbtB0GMxB1bHLTkWgD6PV6ejArClJPvDc9rDrOwIDAQABo4GM
    MIGJMA4GA1UdDwEB/wQEAwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
    AwIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUO2IRSDwqgkZt5pkXdScs5Bjo
    ULEwKAYDVR0RBCEwH4IdVmVsb2NpcmFwdG9yX2NhLnZlbG9jaWRleC5jb20wDQYJ
    KoZIhvcNAQELBQADggEBABRNDOPkGRp/ScFyS+SUY2etd1xLPXbX6R9zxy5AEIp7
    xEVSBcVnzGWH8Dqm2e4/3ZiV+IS5blrSQCfULwcBcaiiReyWXONRgnOMXKm/1omX
    aP7YUyRKIY+wASKUf4vbi+R1zTpXF4gtFcGDKcsK4uQP84ZtLKHw1qFSQxI7Ptfa
    WEhay5yjJwZoyiZh2JCdzUnuDkx2s9SoKi+CL80zRa2rqwYbr0HMepFZ0t83fIzt
    zNezVulkexf3I4keCaKkoT6nPqGd7SDOLhOQauesz7ECyr4m0yL4EekAsMceUvGi
    xdg66BlldhWSiEBcYmoNn5kmWNhV0AleVItxQkuWwbI=
    -----END CERTIFICATE-----
  nonce: rKNKAYam310=
  writeback_darwin: /etc/velociraptor.writeback.yaml
  writeback_linux: /tmp/1/velociraptor.writeback.yaml
  writeback_windows: $ProgramFiles\Velociraptor\velociraptor.writeback.yaml
  max_poll: 600
  windows_installer:
    service_name: Velociraptor
    install_path: $ProgramFiles\Velociraptor\Velociraptor.exe
    service_description: Velociraptor service
  darwin_installer:
    service_name: com.velocidex.velociraptor
    install_path: /usr/local/sbin/velociraptor
  version:
    name: velociraptor
    version: 0.6.4-rc4
    commit: f3264824
    build_time: "2022-04-14T02:23:05+10:00"
  pinned_server_name: VelociraptorServer
  max_upload_size: 5242880
  local_buffer:
    memory_size: 52428800
    disk_size: 1073741824
    filename_linux: /var/tmp/Velociraptor_Buffer.bin
    filename_windows: $TEMP/Velociraptor_Buffer.bin
    filename_darwin: /var/tmp/Velociraptor_Buffer.bin
API:
  bind_address: 127.0.0.1
  bind_port: 8001
  bind_scheme: tcp
  pinned_gw_name: GRPC_GW
GUI:
  bind_address: 127.0.0.1
  bind_port: 8889
  gw_certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDQTCCAimgAwIBAgIQDjTKeeNNI7qTjgfcySUFwDANBgkqhkiG9w0BAQsFADAa
    MRgwFgYDVQQKEw9WZWxvY2lyYXB0b3IgQ0EwHhcNMjMwNTA4MTkwODM5WhcNMjQw
    NTA3MTkwODM5WjApMRUwEwYDVQQKEwxWZWxvY2lyYXB0b3IxEDAOBgNVBAMMB0dS
    UENfR1cwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtD84tm8nvXRRP
    d3T6QdgA6+OKvTLvGhxZ/PfxsJYbjQXKmZzbpDYqJ+UdxV3dyvDgroiIQkSfRSIS
    QUexVn7Pk+KkAFyQeki8yXxoUXUcm00OV/RouQ1Pv7wVG6iqpg7E2BGSsZkgPNIP
    tpJ4GkeQsCLC6Qo4S1gIXpq5V6DI8pHb2EffiLwopKEfBFGQJTXOz116FtMcwmxg
    aHF8LYlwUZu8dyDBolSQcIP2qaklnud+x7raNqtoUQG+YO+97KP89Ng8tjWEgQe1
    +KAKiy82ZwpufnWZzHzuNG/7zUR7WmuAGSbs+/6WnDJ61oRSLUJPR3aYvBgqVrgm
    IwbCfdkLAgMBAAGjdDByMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
    BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ7YhFIPCqC
    Rm3mmRd1JyzkGOhQsTASBgNVHREECzAJggdHUlBDX0dXMA0GCSqGSIb3DQEBCwUA
    A4IBAQA9HYMmyV7rkznp6cp4JyHHsjLvsPnJLu4+QwtQ9G24mn5PiZU/UDQ2RcRZ
    9Tu58wmtULCGmdV1JYkmJHnatQvlBRz/FLJSB1mjyiRkE9SHFDK+QepHOwR/x1Sk
    iXe5DbUOjw0VUF95aj2BgURKkBpn6OH7/4RFc5R0aJ6wpg89MTZBp8++7Ky7/7BT
    UzCVtDSnY788/RlzqiRPRWq2WOz204b7wtTEeRy9mJHUIwi/1HT1iTTTQr42j9z1
    vGKcz4f1Mlkk1Wz5O2DFUiKUsK/deH8xUvZoygTJrbchFiPkvQiNzqw+2VTa+D+i
    wS4jQijC8RmedmPVgXd0bakHY1A+
    -----END CERTIFICATE-----
  gw_private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEArQ/OLZvJ710UT3d0+kHYAOvjir0y7xocWfz38bCWG40Fypmc
    26Q2KiflHcVd3crw4K6IiEJEn0UiEkFHsVZ+z5PipABckHpIvMl8aFF1HJtNDlf0
    aLkNT7+8FRuoqqYOxNgRkrGZIDzSD7aSeBpHkLAiwukKOEtYCF6auVegyPKR29hH
    34i8KKShHwRRkCU1zs9dehbTHMJsYGhxfC2JcFGbvHcgwaJUkHCD9qmpJZ7nfse6
    2jaraFEBvmDvveyj/PTYPLY1hIEHtfigCosvNmcKbn51mcx87jRv+81Ee1prgBkm
    7Pv+lpwyetaEUi1CT0d2mLwYKla4JiMGwn3ZCwIDAQABAoIBAF2w6NYYOUK1CYHc
    EiBJ9T7Kde1ucFyxrheptDHMf/d6aWA9uYXPaON5pbhwWVjxvWZmFtRty+jN7Jwl
    a0K+qPiH/3L6HyK4kRhjnE59iwFpslXJmC/5vxMlohVrW+zG6cf3kcvxCg1B4BdR
    qAoNcCEMukT7FOVVJNujG/CrWAhxJXamJIAQYArEDwcCU2ANP0fSB2zWLksqCwxf
    62uQc+y1hMY9+f0F2qQlzLImLsL6OV/ca5h7R9wf2U1mFmumH2Wx22x+99nkBb0U
    4uv0v+UaWDVISFoLX3mnJhazuJj5+E1BzJPKC+ankS/BfrhrH3lTop8K2J8I9MdC
    Zv5A9oECgYEA5V/C+itZbR0Dl+RSB3XY0Blk2qfSAgw1h1e1t77gf/Olm9qj1H8K
    YYjp06ZOg3gTeV1RXTbzXnGMPZCUi94y/8RVQh1wm4ZVIU3A8rljD7/KFcYOdDOt
    d4tunb5OsfREdr3STPJ9kT7DjVKvZ58Bh+PnPg8USnvrwy9Hd3cTWHkCgYEAwSag
    rlgyilyVmBIbjvLejk8QeBfXhmtnRbsY9C/3yMzlXXsstWi/1o7EY161TavdE4x+
    /82U6wNL6eRDnhqDA40tk3qSZibWh+g6N3+9xR0vPouwJwRtdIX+VWbPj/Q4hdJO
    +iW88WhUdh4lvN3QhvTZS2TJ+kmQn01jzD63pKMCgYEAm0Uz672kj6RwZkX88Wfp
    GRXXm9y24QP6yF+rd3MS7gq1NMfQ12wYTuYrw0Z1J7IFHMb66SrlnC0pThOtOvFz
    fIgfXt4m+GD7B8xmrOiqEmM2HX8xEaBZ8O7GNqo5A2XjYq4kyknsjoH6RpSOgIq2
    spKoWu5CQhmZA0viCRDmW6ECgYB9nN5wo+EyhGWxQU102NQOHrMqNu8udxjxi2z+
    GVf+2ensspdv3xCru6tSqJwmSDf9Z6iMOam4cStkj9O9taYwoBbcy6D8GBP6zPdX
    cpb64zD/bx7/MOzyE9ZEuhkQmJZNyWkdW3+WS/Bp5M9MFcFwkznhw0lroX4Ra+YU
    RVFvGwKBgQCLcCWJlRj9/aiSZHDULEOjkcQtEXs559caI7zsNZi3McT5Hchc4d72
    ZcmZJ2557pX0S1jxVWNLwNuduFG15CxeT8T7qJUj94TlDC0B+a3iViI9RT7JPpzA
    UQHly5p6VcvHinpgEpvDeEc+N+iAbDUkmzIzfJRD1Rfox4LlVi/EXQ==
    -----END RSA PRIVATE KEY-----
  internal_cidr:
  - 127.0.0.1/12
  - 192.168.0.0/16
  authenticator:
    type: Basic
CA:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAsLO3/Kq7RAwEhHrbsprrvCsE1rpOMQ6QrJHM+0zZbxXchhrY
    Evi7W+Wae35ptAJehICmbIHwRhgCF2HSkTvNdVzSL9bUQT3QXANxxXNrMW0grOJw
    QjFYBl8Bo+nv1CcJN7IF2vWcFpagfVHX2dPysfCwzzYX+Ai6OK5MqWwk22TJ5NWt
    UkH7+bMyS+hQbocr/BwKNWGdRlP/+BuUo6N99bVSXqw3gkz8FLYHVAKD2K4KaMlg
    fQtpgYeLKsebjUtKEub9LzJSgEdEFm2bG76LZPbKSGqBLwbvx+bJcn23vb4VJrWt
    btB0GMxB1bHLTkWgD6PV6ejArClJPvDc9rDrOwIDAQABAoIBAAo6vUIBWEn+MBzD
    SAi080S3cNZFftVUNIfpAObjcgr+Rv/0eeHPSHlvd1wC23eyU2p0UC4j75b/OM/F
    t/z0a1aKAxkF5M/KFk/dWy7FGcWIvcWEbl9GoAPuaBfnKR0tDVmOEsy0P08HdU8L
    9+UCYiBvAK1eQlD3oGA7pvB/9DpHKLSiZOBtmss0EXuJdixKvlcF6GPHBpAjG90g
    ogwcRXJt8qJm9/N5pz+3odYFttXwBn7bdxNLBaUkG3RvrFHUslmN7V0tvFIpjAIT
    f7/5jmLhJugoP6wl9hUEsUSrcdRmSYKRNuHFU06OazBTlka4ksM3z2RFJ6TRhxXZ
    s8U8o3ECgYEAwYKeDJQcx+gRC26Vq6EWT5oHZOLrTh5QrZv/cBo0YP8nhLR0uzwz
    HNj8sMgyFV8yLCYvWaqgRCfCwMoMAUQCH5q0GPNxlQuaL+3WjcTwQeTPms9IuMFh
    rTDt1mi3xPwc5n8ZNafB8+1cNJKOCvrKXdxM/kmRIJVUaFREjyM+LgUCgYEA6cOT
    sl2fp80n10VONcFeVIEaN+YjBapDBJzaNThxTVzjBRsPyUzgEIhQ6r6V8LmG56Wo
    VfyELuvNHgKYvA6mIlsH6l3SLq+F7ohwEDVikp0yzjiMRRhhxQUsnahtHhX3JsUd
    yX2hQOLaaNfNV7gYx64a4iWizFrEa9J2wSUQuD8CgYEAmHZD9h8gCfTysPIg5EeX
    34G4/6i1wieqYw58lCNhT2bZCPpw2jBVCQ6BEPu6UhJd4mD3f4sqmGhHTkQib0DY
    93OZH+t2evrYMZkPKUWYEiKn2w4j+sUKIz1gtkRtPbtxPb237AlPi9NgiV9KoKX1
    mTwAQX1O5cAh780s8yXOUM0CgYA/zC6c+Uw/YZBEAhgsN4/lBC8Bnn9kZmlP8vbi
    m3rgoD8c/5u5Vo+4M1vSFR2ayyd0RRPCE96HZ7ddP1wrxtu0eJ+aaOyZ7TFiPj5H
    TiqO1PQur+QoX1Ufjh/1Dyhok5oWLKnKeczuhnsRLgROsmGg7XVMzvS1TPhabOAY
    KmN7xQKBgEnOjlbCT24fvolHxSJETuoq5IHjwnB/DKTMfnsFfqDPgC/rljqQMF5v
    yzPC/h0xqCh/dI7pIsJ5FjEXOtIJT/sWa1iddB7WC2oFh6AIrVJszt0dQx+4lS2m
    OgdvbViAVYsGELhg/EeJs/ig1v27BMcv2aQtZXTEHXmOd2xL93l5
    -----END RSA PRIVATE KEY-----
Frontend:
  hostname: localhost
  bind_address: 0.0.0.0
  bind_port: 8000
  certificate: |
    -----BEGIN CERTIFICATE-----
    MIIDVzCCAj+gAwIBAgIQRtxHx63osIed/9/zcXWK4zANBgkqhkiG9w0BAQsFADAa
    MRgwFgYDVQQKEw9WZWxvY2lyYXB0b3IgQ0EwHhcNMjMwNTA4MTkwODM5WhcNMjQw
    NTA3MTkwODM5WjA0MRUwEwYDVQQKEwxWZWxvY2lyYXB0b3IxGzAZBgNVBAMTElZl
    bG9jaXJhcHRvclNlcnZlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
    AJ0sZr9kSRUkM5lnOTP9dn34XaT0ZioEqyCvGOTWlKnT1VI3uQOdwwiwvFdB6Dvv
    8txhUkA9DlDSdgmPkziaa3YbzD13sreB1gbOZYRtPEb9pIeBLcW+LWhUpWZoO6VN
    2SvKJ/crXHwdbbq3mmHSlRv9OmB48H855WQ+WVscoYFHrBZ12kvMKH/p1j30UyMJ
    l9uSJ7Y7QfhtTcv8UpC7oseIamWXO5F4nFfScNmCu+H/Xg/ncdZOPqBhOSeNBB8j
    ZpzYDKAO+AjhJcPI+4JXsGHF8n6V9gwnlY7ciUW7ZXt39TMtlRq8DBDTJ8exvm0h
    Gx7EdmvPhVXH8EGWgFCKmUsCAwEAAaN/MH0wDgYDVR0PAQH/BAQDAgWgMB0GA1Ud
    JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQY
    MBaAFDtiEUg8KoJGbeaZF3UnLOQY6FCxMB0GA1UdEQQWMBSCElZlbG9jaXJhcHRv
    clNlcnZlcjANBgkqhkiG9w0BAQsFAAOCAQEAW8WN1y+tS7fkg4W2+ZrbNZE36O/O
    Cs9TAEZEgjbBDqEVm33v44ThYVXWgq9BNyU6XVV8SQPbRPVRvoa7jFYNVLEhtdb8
    H5VvIwhN4u/e3R0IvHfhX0RegyR6PqfGfPOrqhubXnqGhVSmA8/TWp2l2XrtLpak
    SCWH1IfXVlrdbL3fhotD7DGTpie5uKI6EOwzsTmYBWIyBQ7TTqi5tq+SOp49HXiv
    IQVAo2jqqjqEZhLm/rHJJ3Tck5YPETzjcO1jqYX/5glZJb+yJAfX3Ge3Fm1x1XRj
    BhmRGAZyp43CnAqb1vrEbdC1aCYqmJ/8HTqp5ZMQURuike5+ZLhnrxayDw==
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAnSxmv2RJFSQzmWc5M/12ffhdpPRmKgSrIK8Y5NaUqdPVUje5
    A53DCLC8V0HoO+/y3GFSQD0OUNJ2CY+TOJprdhvMPXeyt4HWBs5lhG08Rv2kh4Et
    xb4taFSlZmg7pU3ZK8on9ytcfB1tureaYdKVG/06YHjwfznlZD5ZWxyhgUesFnXa
    S8wof+nWPfRTIwmX25IntjtB+G1Ny/xSkLuix4hqZZc7kXicV9Jw2YK74f9eD+dx
    1k4+oGE5J40EHyNmnNgMoA74COElw8j7glewYcXyfpX2DCeVjtyJRbtle3f1My2V
    GrwMENMnx7G+bSEbHsR2a8+FVcfwQZaAUIqZSwIDAQABAoIBAEm+8Z7P0TKoP8W0
    lzR7ssM8a8PgIKeKdTjqr0WAIVTl3eur1ZWKyl4jftt6QxsMZOleiJc3jqYBefzW
    bv9aBR3vwQ7+QM61jtS2tw9BqcytaitiQzXLG8ceIFVChuny8vkG62Wf5M8fh8La
    LwfDJM9zK5bkaANqCOXWE1savfTIDgp+c+/UrYQJ2A2yovf9GloKFF/6IYWsQv/O
    xyiKqC9hvTG8F74b5ElRtIx0h5zrMa1iXzIFe6tbMD8Anb0IUxrtnqzfyTP+6Et5
    L/mDlHcLEoS7iYWbdIvGzkI6llIMTTfTKsvv+ppyVm3LkoGRwazHZmQ1MSjOgEYa
    2jvKtIECgYEAyi32LKBwoidd3JgAjms+RFEjFMe16AHbVfT3onFy7xrLCLLGKb/q
    7Jm8psdF6654MS1m03dMMQ/wdcQH3JjhM7igZZxjOQ7EVJ5/to+kKsN2oFd6JUtc
    MvSMTtMVDshAovulKkQU6vp4DBYlynqu72MPw+vFtIY+A8pgRIU0wisCgYEAxwNi
    keTlbcwW2v+oq2d0l259rEPM0bKnrLZztHC5ALdDcidKzhmFAiKjEbMwJEpZWTQO
    QkH/UywuZeUnLF9lYUTiNLBD4U/cejXw4H2E97Oo1k8E60SGPBjHVBBwSXDotDyf
    7CtuJaVgA0Qrj6s2nl3nuJSwNVzNu1eIjOSelWECgYA2XcufznjbMcjMo9cqdO4m
    gsbzNIzW2YD4iUn51ZX5c/P638/ntCLhAqo3EsjbimvplXLcFG1ZmBaqJE+U40tT
    lCcVi8smsbDbrE9dcRzNHwiML1m6I5ykWxxLqfk0o2a2LQMJ7YrOcRHM9jutSfY2
    iyXXIlRkqeCNNmNSqZs5RwKBgDZY1U00Lfc6+a7ajEwql2tXMBif90n4uNNwi85l
    zg/E/DUrR8FatLjtjoyh2269owK6NX6gmUI0WYNX/cefUYcrkX6D+DWKYpI5MsuL
    W4ltVZkYwSYic2nr9lsdlhxoKhQ2ThHnlk/PhpW9wwub3PGIgWQlrq0T59bWQ6L+
    N9RhAoGBAKa+LyF61JmlFwvCW/qaA3eDHO2dhei0gtQ9mgQrv3wCEsT65bh3wjau
    6jnvg4gNhfspC2T98493xWqQSrYtvhWibYxPFZS5kQfaA3tQPGRfm2oj9l3jo/lp
    HPnGQkDC8tRRD+Mvpsl0HWNmfUVq2eYj9JefON80P0YmRy21UjbX
    -----END RSA PRIVATE KEY-----
  dyn_dns: {}
  default_client_monitoring_artifacts:
  - Generic.Client.Stats
  GRPC_pool_max_size: 100
  GRPC_pool_max_wait: 60
  server_services:
    hunt_manager: false
    hunt_dispatcher: false
    stats_collector: false
    server_monitoring: false
    server_artifacts: false
    dyn_dns: false
    interrogation: false
    sanity_checker: false
    vfs_service: false
    user_manager: true
    client_monitoring: false
    monitoring_service: false
    api_server: false
    frontend_server: true
    gui_server: false
    index_server: true
    journal_service: true
    notification_service: true
    repository_manager: false
    test_repository_manager: true
    inventory_service: true
    client_info: true
    label: true
    launcher: true
    notebook_service: false

  resources:
    connections_per_second: 100
    notifications_per_second: 10
    max_upload_size: 10485760
    expected_clients: 10000
Datastore:
  implementation: Test
Writeback:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEArmgftoc6pi/ZMGZO40UIKXlscTXrZWifDtTGsAhXfaKG4xzu
    LLLIM4Cr+L3ctYgFkWyczXst6Tx6zRyU/l2OqaWmJjhNwXlRwNajx+2ZqTa5zA8r
    lr+QeYrg19+Acmgb8DkPwp8in/f3tHl7Na8U8GE/3CX4nMsLOzcfAEdH/4IRh3b0
    3VW361dlBL8Sw2KJ7ECmhujjtlxu7BUDolxxf8bIkFDVt/nhs9xxm2yI+b2xQnsy
    LDHpsZzSuXj/M38s8u0r59QtJ+ByjFjte+gjGpTc9WlMytTvI/RJUbiEKwOPjBVn
    BcV/1IZ08KokSfhq4xpVY/GPZVL4CEf/ZOo9rQIDAQABAoIBAFnNUW75yHAjuRBb
    zYjmVaKNXBIa8l8f9K59TuT7FpmhIxU0I0surzkdqu8ES+3I4R0VMNP49hXfR1fv
    vKQQ5lFh8uBBI4BYiIjjvCdIp1Ni015H/Wi8sJZ0tPtSoN/HzYLuzremmvyFgK0T
    1CY7RWvUlz4y6wVI4zqVUkgha+gaZjoQklzamwqKHQwqtFyPVISmSp6XL/zexk95
    GVUGps4mtsXWUsSnsmlUD5Ola/7hXeEgbD1nj2Znobu9z0y8mDlIhpFpQJwu36KB
    3o3tqBOXuoukxmsvuW8QxW1xzCICuh8CU5g6kWkyNJOsf4X5Y2js/5Zo9dbLkOrd
    VEnnV+ECgYEAydqTmbWQyOeUxV9mfD2BbjnzLvxMCCggW/i4TGYhtLweO7UPSiQT
    /zK0KX317vupUou//vGEcFKLPVu4xchsGrayOVCWEpurqvZfPmg9lWyF2fi8rZK0
    vOWCw8HIgIbb8EvRCH1v0gNMdzjaf1qLN28W5H/7re4rruQOEuyv29kCgYEA3TC9
    XFAVSePV/Ky22AdbccVacABmM5RAneot/E7DTrA9uGujUB+9kCPIDsPLCjT2uXj/
    yP/a210t8KZBtvW+1Ums06titw65lkG7rjapB08vjF1aD0bjPE4R1uapm+CM6dlm
    oc3Beb8kyA+bXZMpnJT1KtAI3/zrdlZkhQlAL/UCgYAs/uViIUAqGL1oFfERhuBg
    Qti7w4/rTY6REet7VFT1Je4TXzQOUeaHP7U7fpGg+UZwWSiuWwYrx6q0Pcr9g8Td
    W5Z1AkrB0SO+U3c9wRzhPzTDNxhQFODnLr4shvj79ZP3h98L5nJTvVqBRRIny3Y3
    IDNZMlJXHj1smfetLkexWQKBgBgcgAfYEvoDBAiPKz9RTf6Q7NLYuEtXFdQg+vJO
    A6xIOfIoiZzqWNeljuFNJozuSRbewcM/YLQY7DEXboJrN2o4pcZNIG2kBUcD01mi
    S7qoPx6l7nNL3ulr+TXb3xFG4RV8xVtN+pEy7OeCDAWfTSHseu030D/aajB0KnD2
    GTEhAoGARB/E6j/WX+CBPWiF4XLV03F1hEMYY/ZSfijcZQniCNtRQUuIkTMiSv1E
    LZ5KmiY35bmYwkGOST6sd9T586nNEdIfs2ngcXwRcgPmQU7VaKQdeVnxhEG2xXFG
    NtyI/STijkpVi99wF39BvXkQGdJuDjAArjGj5kevCpvyveudL5g=
    -----END RSA PRIVATE KEY-----
Mail: {}
Logging:
  debug: {}
Monitoring:
  bind_address: 127.0.0.1
  bind_port: 8003
api_config: {}
obfuscation_nonce: RzlAlmdcUyw=
defaults:
  hunt_expiry_hours: 168
  notebook_cell_timeout_min: 10
`
