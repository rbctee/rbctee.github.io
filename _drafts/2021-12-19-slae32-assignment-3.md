---
title: "SLAE x86 Exam - Assignment #3"
date: 2021-12-21
toc: true
search: false
classes: wide
categories:
  - blog
tags:
  - slae
  - assembly
  - nasm
  - c
  - exam
  - shellcode
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The second assignment requires you to write shellcode for an `Egg Hunter`. Moreover, it should be *configurable for different payloads*.

## Theory

Now comes the question: what is an *Egg Hunter*?

According to a [paper](https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf) from `Exploit-DB`:

> When the "Egg hunter" shellcode is executed, it searches for the unique "tag" that was prefixed with the large payload and starts the execution of the payload.
> [...]
> The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode. Instead, a unique "tag" is prefixed with shellcode.

## Practice
