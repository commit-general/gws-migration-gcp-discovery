# Google Cloud discovery

<walkthrough-tutorial-duration duration="20"></walkthrough-tutorial-duration>

## Before you start

This tutorial runs a read-only script that describes your Google Cloud
organization: who has access to what, and what is tied to your company's
accounts. We use it to plan your Google Workspace migration so that no access
breaks.

- It runs with your own sign-in, in this temporary Cloud Shell session.
- It changes nothing in your organization. The one optional exception is
  explained when it comes up, and you can say no.
- It writes one zip file, which you download and upload in the form.

You need an account that can view your whole organization, for example an
organization admin. The script tells you if a part can't be read, and which
role would fix it.

Click **Start**.

## Sign in

This session doesn't have your credentials yet. Sign in with your work
account:

```bash
gcloud auth login
```

Open the link it prints, choose your work account, allow access, and paste
the code back here.

## Run the script

```bash
./gcp_discovery.sh
```

The script shows what it will read and asks you to type **YES**.

If your account can see more than one organization, it asks which one.

## Wait for it to finish

The script prints its progress. First it checks your access, one small read
per area. A ✗ means that area will be partial; the line says which role
would fix it. You can let it continue.

**Budgets.** Budgets can only be read through a project where the Cloud
Billing Budget API is on. If none of your projects has it on, the script asks
whether to turn it on in one project you pick. It's free, and changes only that
project. Type **NO** to skip budgets.

Reading the audit logs is the slow part. Most runs take 5 to 10 minutes.

## Download the zip

At the end, the script prints a summary and the zip's path, and offers to
download it. Type **YES**.

If you missed it, run this to download it again:

```bash
cloudshell download gcp-discovery-*.zip
```

Cloud Shell deletes the file when this session ends, so download it before
you close this tab.

## Upload it in the form

Upload the zip in the form you were sent, in the question **Discovery script
output (zip)**.

The zip holds the email addresses of people and service accounts in your
organization. It holds no passwords, keys or tokens. Share it only through
the form.

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>

Thank you. You can close Cloud Shell now.
