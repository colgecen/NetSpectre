"""permissions.py birim testleri — /proc okumaları sahtelenir, root gerekmez."""

import pytest

from netsentinel.permissions import (
    PermissionStatus,
    check_permissions,
    ensure_scan_permissions,
    parse_cap_eff,
    read_cap_eff,
)

# Hesap: CAP_NET_ADMIN(12) + CAP_NET_RAW(13) = 0x3000
CAPS_ALL = "000001ffffffffff"  # tipik root yetenek seti
CAPS_YALNIZ_RAW = "0000000000002000"
CAPS_YOK = "0000000000000000"


class TestParseCapEff:
    def test_iki_yetenek_de(self):
        caps = parse_cap_eff(CAPS_ALL)
        assert {"CAP_NET_RAW", "CAP_NET_ADMIN"} <= caps

    def test_yalniz_net_raw(self):
        assert parse_cap_eff(CAPS_YALNIZ_RAW) == {"CAP_NET_RAW"}

    def test_yetenek_yok(self):
        assert parse_cap_eff(CAPS_YOK) == set()

    def test_gecersiz_metin_bos_kume(self):
        assert parse_cap_eff("toz-duman") == set()
        assert parse_cap_eff("") == set()


class TestReadCapEff:
    def test_status_dosyasindan_okur(self, tmp_path):
        status = tmp_path / "status"
        status.write_text("Name:python\nCapEff:\t" + CAPS_YALNIZ_RAW + "\nCapBnd:xxx\n")
        assert read_cap_eff(status) == CAPS_YALNIZ_RAW

    def test_satir_yoksa_sifir(self, tmp_path):
        status = tmp_path / "status"
        status.write_text("Name:python\n")
        assert read_cap_eff(status) == "0"

    def test_dosya_yoksa_sifir(self, tmp_path):
        assert read_cap_eff(tmp_path / "yok") == "0"


class TestCheckPermissions:
    def test_root_her_seyi_yapabilir(self):
        st = check_permissions(geteuid=lambda: 0, cap_reader=lambda: CAPS_ALL)
        assert st.can_scan and st.can_passive
        assert st.mode_label == "root"
        assert st.warnings == []

    def test_setcap_li_kullanici_tam_yetkili(self):
        st = check_permissions(geteuid=lambda: 1000, cap_reader=lambda: CAPS_ALL)
        assert st.can_scan
        assert st.mode_label == "yetkili (setcap)"
        assert st.warnings == []

    def test_yetkisiz_kullanici_aktif_tarama_yapamaz_uyarir(self):
        st = check_permissions(
            geteuid=lambda: 1000,
            cap_reader=lambda: CAPS_YOK,
            python="/x/.venv/bin/python",
        )
        assert not st.can_scan
        assert not st.can_passive
        assert len(st.warnings) == 1
        assert "setcap" in st.warnings[0]
        assert "/x/.venv/bin/python" in st.warnings[0]
        assert st.mode_label == "sınırlı (yalnızca pasif)"

    def test_yalniz_root_olmadan_kismi_yetenek_pasif_icin_yeter(self):
        st = check_permissions(geteuid=lambda: 1000, cap_reader=lambda: CAPS_YALNIZ_RAW)
        assert not st.can_scan  # NET_ADMIN eksik
        assert st.can_passive  # ama dinleme yapılabilir


class TestEnsureScanPermissions:
    def test_yetkili_gecer(self):
        st = PermissionStatus(is_root=True, has_net_raw=False, has_net_admin=False)
        ensure_scan_permissions(st)  # exception beklemiyoruz

    def test_yetkisiz_permissionerror(self):
        st = PermissionStatus(
            is_root=False,
            has_net_raw=False,
            has_net_admin=False,
            warnings=["CAP_NET_RAW gerekir, setcap uygulayın"],
        )
        with pytest.raises(PermissionError, match="setcap"):
            ensure_scan_permissions(st)
