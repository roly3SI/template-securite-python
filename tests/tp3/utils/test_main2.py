from unittest.mock import patch, MagicMock, mock_open
from src.tp3.main import breach_web, breach_network, main


@patch("src.tp3.main.requests.get")
@patch("src.tp3.main.Session")
@patch("builtins.open", new_callable=mock_open, read_data="admin\npanel\n")
def test_breach_web(mock_file, mock_session_class, mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_get.return_value = mock_resp

    mock_session = mock_session_class.return_value
    mock_session.get_flag.return_value = "ESGI{web_flag}"
    mock_session.tcp_host = "127.0.0.1"
    mock_session.tcp_port = 9090
    mock_session.tcp_key = b"deadbeef"

    host, port, key = breach_web("http://127.0.0.1:8080")

    assert host == "127.0.0.1"
    assert port == 9090
    assert key == b"deadbeef"


@patch("src.tp3.main.remote")
def test_breach_network(mock_remote):
    mock_conn = MagicMock()
    mock_remote.return_value = mock_conn

    mock_conn.recvline.return_value = b"Felicitation : ESGI{network_flag}\n"

    flag = breach_network("127.0.0.1", 9090, b"deadbeef")

    assert flag == "ESGI{network_flag}"


@patch("src.tp3.main.breach_network")
@patch("src.tp3.main.breach_web")
@patch("src.tp3.main.argparse.ArgumentParser.parse_args")
def test_main(mock_args, mock_breach_web, mock_breach_network):
    mock_args.return_value = MagicMock(target="http://127.0.0.1:8080")

    mock_breach_web.return_value = ("127.0.0.1", 9090, b"deadbeef")
    mock_breach_network.return_value = "ESGI{final_flag}"

    main()

    mock_breach_web.assert_called_once_with("http://127.0.0.1:8080")
    mock_breach_network.assert_called_once_with("127.0.0.1", 9090, b"deadbeef")
