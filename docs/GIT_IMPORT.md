# Import Shield into a writable Git repository

`tradedeck-shield-source.bundle` is a standalone Git bundle with one `main` commit. The source ZIP contains the same files without Git metadata. Keep Shield in its own repository and leave the existing TradeDeck Flask service untouched.

On a computer with Git, create an empty private repository under an account that can push to it, then import the bundle:

```sh
git clone -b main tradedeck-shield-source.bundle tradedeck-shield
cd tradedeck-shield
git remote remove origin
git remote add origin https://github.com/YOUR_ACCOUNT/tradedeck-shield.git
git push -u origin main
```

Replace `YOUR_ACCOUNT` with the account that owns the empty repository. Do not paste tokens, keystores, or service-account JSON into Git. After the push, check that all three GitHub Actions jobs pass. The Android and iOS jobs compile unsigned debug/simulator builds; they do not perform release signing or device attestation.

Then connect the new repository in Render as a **separate** Shield service using the root `render.yaml`. It selects a paid Starter instance and a 10 GB persistent disk. Configure the secrets marked `sync: false` and review charges before applying the Blueprint.
