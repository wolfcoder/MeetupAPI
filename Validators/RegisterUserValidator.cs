﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentValidation;
using MeetupAPI.Entities;
using MeetupAPI.Models;

namespace MeetupAPI.Validators
{
    public class RegisterUserValidator : AbstractValidator<RegisterUserDto>
    {
        public RegisterUserValidator(MeetupContext meetupContext)
        {
            RuleFor(x => x.Email).NotEmpty();
            RuleFor(x => x.Password).MinimumLength(6);
            RuleFor(x => x.Password).Equal(x => x.ConfirmPassword);
            RuleFor(x => x.Email).Custom((Value, context) =>
            {

                var userAlreadyExists = meetupContext.Users.Any(user => user.Email == Value);
                if(userAlreadyExists)
                {
                    context.AddFailure("Email", "That Email address is taken");
                }

            });


        }
    }
}
