class CryptoAc
{
    [void]temp($path)
    {
        if(([System.IO.File]::Exists($path)) -eq $false)
        {
            mkdir $path
        }
    }

    [array]xorBytes($a,$b)
    {
        [array]$xored = @()
        for ($i=0; $i-lt $a.Length; $i++)
        {
            $xored += ($a[$i] -bxor $b[$i])
        }
        return $xored
    }

    [array]randKey($key)
    {
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        return $sha512.ComputeHash($key)
    }

    hidden [array]spliter($data,$pointer)
    {
        $block = @()
        for ($i=$pointer;$i-lt $pointer+64;$i++)
        {   
            $block += $data[$i]
        }
        return $block
    }

    [array]randFirstKey($data,$key)
    {
        $h = ([CryptoAc]::new()).randKey($data)
        $nkey = ([CryptoAc]::new()).xorBytes($h,$key)
        return $nkey
    }

    [array] genKey($password)
    {
        return ([CryptoAc]::new()).randKey([byte[]][char[]]$password)
    }

    [array] fKeyDecrypt($data,$key)
    {
        $hdata = @()
        for ($i=0; $i-lt 64; $i++)
        {
            $hdata += $data[$i]
        }
        $nkey = ([CryptoAc]::new()).xorBytes($hdata,$key)
        return $nkey
    }

    hidden [array]pad($data)
    {
        $p = ($data.Length)
        if ($p -lt 64)
        {
            $p = 63 - $p
            $data += @(124)
            while ($p -lt 64)
            {
                $data += 0
                $p+=1
            }
        }
        Elseif(($p%64)-ne 0)
        {
            $data += @(124)
            $p = 64 - (($p % 64) + 1)
            while($p -ne 0)
            {
                $data += 0
                $p-=1
            }
        }
        else{
            for ($i=0; $i-lt 63; $i++)
            {
                $data += 0
            }
            $data += 110
        }
        return $data
    }

    hidden [array]unpad($data)
    {
        $c = 1
        if(($data[-1]) -eq 110)
        {
            return $data[0..(($data.Length) - 65)]
        }
        while(($data[-$c]) -eq 0)
        {
            $c+=1
        }
        return $data[0..(($data.Length)-($c+1))]
    }

    [array] encrypt($data,$key)
    {
        $data = ([CryptoAc]::new()).pad($data)
        echo ([CryptoAc]::new()).randKey($data) > "$env:APPDATA/ENENENACACAC.key"
        $key = ([CryptoAc]::new()).randFirstKey($data,$key)
        for($i=0; $i-lt $data.Length; $i+=64)
        {
            $block = ([CryptoAc]::new()).spliter($data,$i)
            $res = ([CryptoAc]::new()).xorBytes($block,$key)
            $key = ([CryptoAc]::new()).randKey($key)
            echo $res >> "$env:APPDATA/ENENENACACAC.key" 
        }
        $res = Get-Content "$env:APPDATA/ENENENACACAC.key" ; Remove-Item -Path "$env:APPDATA/ENENENACACAC.key"
        return [System.Convert]::ToBase64String($res)
    }

    [array]decrypt($data,$key)
    {
        $data = [System.Convert]::FromBase64String($data)
        $key = ([CryptoAc]::new()).fKeyDecrypt($data,$key)
        for($i=64; $i-lt $data.Length; $i+=64)
        {
            $block = ([CryptoAc]::new()).spliter($data,$i)
            $res = ([CryptoAc]::new()).xorBytes($block,$key)
            $key = ([CryptoAc]::new()).randKey($key) 
            echo $res >> "$env:APPDATA/ENENENACACAC.key"
        }
        $res = Get-Content "$env:APPDATA/ENENENACACAC.key" ; Remove-Item -Path "$env:APPDATA/ENENENACACAC.key"
        return ([CryptoAc]::new()).unpad($res)
    }

    [boolean]encryptFile($path,$key)
    {
        $data = [System.IO.File]::ReadAllBytes($path)
        $enc = ([CryptoAc]::new()).encrypt($data,$key)
        # [System.IO.File]::WriteAllBytes($path,$enc)
        $enc | out-file $path
        return $true
    }

    [boolean]decryptFile($path,$key)
    {
        $data = Get-Content $path
        $dec = ([CryptoAc]::new()).decrypt($data,$key)
        [System.IO.File]::WriteAllBytes($path,$dec)
        return $true
    }
}


